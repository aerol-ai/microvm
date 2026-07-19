###############################################################################
# Dedicated observability node (obs1) — NOT a sandboxd cluster member.
#
# When deploy_obs=true, provisions Prometheus + Grafana + Pushgateway on a
# separate EC2 instance outside var.nodes / local.all_instances so bootstrap,
# scrape targets, and Raft membership never treat it as a sandboxd node.
###############################################################################

resource "random_password" "grafana_admin" {
  count = var.deploy_obs ? 1 : 0

  length  = 24
  special = false
}

resource "aws_security_group" "obs" {
  count = var.deploy_obs ? 1 : 0

  name        = "${var.cluster_name}-obs"
  description = "AerolVM observability stack SG"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.cluster_name}-obs" }
}

resource "aws_security_group_rule" "obs_egress_all" {
  count = var.deploy_obs ? 1 : 0

  type              = "egress"
  security_group_id = aws_security_group.obs[0].id
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "All egress (scrape sandboxd nodes, pull images)"
}

resource "aws_security_group_rule" "obs_grafana" {
  count = var.deploy_obs ? 1 : 0

  type              = "ingress"
  security_group_id = aws_security_group.obs[0].id
  protocol          = "tcp"
  from_port         = 3000
  to_port           = 3000
  cidr_blocks       = var.admin_allowed_cidrs
  description       = "Grafana UI from operator CIDRs"
}

# SSH from operator CIDRs — the obs box runs a cloud-init bootstrap (Docker repo
# + compose up); without a shell a bootstrap failure is only visible via EC2
# serial console. Scoped to admin CIDRs (never 0.0.0.0/0), same as the nodes.
resource "aws_security_group_rule" "obs_ssh" {
  count = var.deploy_obs ? 1 : 0

  type              = "ingress"
  security_group_id = aws_security_group.obs[0].id
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = var.admin_allowed_cidrs
  description       = "SSH from admin CIDRs (bootstrap debug)"
}

# Pushgateway is VPC-private — suite/sims push from inside the VPC later.
resource "aws_security_group_rule" "obs_pushgateway" {
  count = var.deploy_obs ? 1 : 0

  type              = "ingress"
  security_group_id = aws_security_group.obs[0].id
  protocol          = "tcp"
  from_port         = 9091
  to_port           = 9091
  cidr_blocks       = [var.vpc_cidr]
  description       = "Pushgateway from VPC (private)"
}

# Arch-2: sandboxd nodes accept :21212 scrapes from the obs SG (not CIDR).
resource "aws_security_group_rule" "node_metrics_from_obs" {
  count = var.deploy_obs ? 1 : 0

  type                     = "ingress"
  security_group_id        = aws_security_group.node.id
  protocol                 = "tcp"
  from_port                = 21212
  to_port                  = 21212
  source_security_group_id = aws_security_group.obs[0].id
  description              = "Prometheus scrape /v1/metrics from obs node"
}

resource "aws_iam_role" "obs" {
  count = var.deploy_obs ? 1 : 0

  name               = "${var.cluster_name}-obs"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_instance_profile" "obs" {
  count = var.deploy_obs ? 1 : 0

  name = "${var.cluster_name}-obs"
  role = aws_iam_role.obs[0].name
}

resource "aws_ebs_volume" "obs_prometheus" {
  count = var.deploy_obs ? 1 : 0

  availability_zone = aws_subnet.public.availability_zone
  size              = var.obs_prometheus_volume_size_gb
  type              = "gp3"
  encrypted         = true

  tags = { Name = "${var.cluster_name}-obs-prometheus" }
}

locals {
  # Embed dashboards as RAW JSON (not base64): templatefile inserts variable
  # values verbatim without re-interpreting ${}/%{} in them, and raw JSON gzips
  # ~8x better than base64 under the outer base64gzip — base64'd dashboards blew
  # past the 16 KB EC2 user_data limit (raw-embed decoded ~7 KB vs ~13 KB).
  obs_dashboard_files = var.deploy_obs ? {
    for f in fileset("${path.module}/../setup/grafana", "*.json") :
    f => file("${path.module}/../setup/grafana/${f}")
  } : {}

  obs_prometheus_yml = var.deploy_obs ? templatefile("${path.module}/../setup/obs/prometheus.yml.tftpl", {
    pat_token      = local.pat_token
    scrape_targets = [for n, inst in local.all_instances : "${inst.private_ip}:21212"]
  }) : ""
}

resource "aws_instance" "obs" {
  count = var.deploy_obs ? 1 : 0

  ami                         = var.ami_id != "" ? var.ami_id : data.aws_ami.ubuntu_amd64.id
  instance_type               = var.obs_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.obs[0].id]
  key_name                    = local.effective_key_name
  iam_instance_profile        = aws_iam_instance_profile.obs[0].name
  associate_public_ip_address = true

  root_block_device {
    volume_size           = var.default_volume_size_gb
    volume_type           = var.default_volume_type
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  user_data_replace_on_change = true

  user_data_base64 = base64gzip(templatefile("${path.module}/templates/obs-bootstrap.sh.tftpl", {
    docker_compose         = file("${path.module}/../setup/obs/docker-compose.yml")
    prometheus_yml_b64     = base64encode(local.obs_prometheus_yml)
    grafana_datasource_yml = file("${path.module}/../setup/obs/grafana/provisioning/datasources/prometheus.yml")
    grafana_dashboards_yml = file("${path.module}/../setup/obs/grafana/provisioning/dashboards/dashboards.yml")
    dashboard_files        = local.obs_dashboard_files
    grafana_admin_password = random_password.grafana_admin[0].result
  }))

  tags = {
    Name    = "${var.cluster_name}-obs1"
    Role    = "obs"
    Cluster = var.cluster_name
  }

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_volume_attachment" "obs_prometheus" {
  count = var.deploy_obs ? 1 : 0

  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.obs_prometheus[0].id
  instance_id = aws_instance.obs[0].id
}
