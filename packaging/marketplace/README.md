# Marketplace listings

AerolVM's Helm chart (`charts/aerolvm`) packaged for two marketplaces:

- `aws-eks-addon/`: an Amazon EKS add-on, listed on AWS Marketplace.
- `azure/`: an Azure Marketplace "Kubernetes application" offer for AKS.

These files are ready, but nothing is listed yet. A seller account and the
legal steps are yours: AWS Marketplace Management Portal for the add-on,
Microsoft Partner Center for the Azure offer. This page says what is done,
what you do, and what to ask each marketplace.

## Before either listing

- **Run the release you list.** Both packages name a release's images
  (`charts/aerolvm/Chart.yaml` `appVersion`, or the tag you give `build.sh`).
- **AKS has not been tested.** The Kubernetes plan's Phase 4 (AKS) was
  skipped. Run its drills on AKS before you submit the Azure offer.
- **Both packages need an API token Secret made first** (key `SB_PAT_TOKEN`).
  A marketplace renders the chart without reading the cluster, so the chart
  cannot keep a token it makes itself: each update would make a new one and
  lock clients out. The install forms ask for the Secret's name.

## Amazon EKS add-on (`aws-eks-addon/`)

| File | What it is |
|---|---|
| `values.yaml` | The add-on's defaults: single mode, the token Secret, the Marketplace registry. |
| `values-cluster-example.yaml` | A cluster-mode setup (three zones, a gVisor pool). Cluster mode needs cert-manager first. |
| `configuration-schema.json` | The settings a customer may change on the add-on (the "configuration values" schema). |
| `check.sh` | Renders the chart as an add-on is rendered and checks it. |

What `check.sh <registry>` checks, the checks AWS's add-on tooling runs:
no Helm hooks, no `.Capabilities`, `lookup` only in the token Secret (which
these values never render), every image from your Marketplace registry,
and a schema whose every setting exists in the chart.

Your steps:

1. In the AWS Marketplace Management Portal, create a container product
   with the EKS add-on delivery option. AWS gives you ECR repositories.
2. Copy the release's four images (`aerolvm`, `aerolvm-runtime`,
   `aerolvm-edge`, `aerolvm-operator`) into those repositories, and the chart
   with `image.registry` set to them.
3. Run `aws-eks-addon/check.sh <your Marketplace ECR registry>`.
4. Submit the chart, `configuration-schema.json` and the values.

Ask AWS during review, because the add-on rules page could not be read when
these files were made:

- The worker pod is privileged, in its own namespace; is that allowed?
- Cluster mode makes that namespace (`cluster.createWorkerNamespace`; set it
  to `false` to make it yourself), cluster-wide RBAC, a validating webhook, a
  PriorityClass and two CRDs. Which does an add-on allow?
- Cluster mode needs cert-manager. Is depending on the cert-manager add-on
  allowed?

## Azure Kubernetes application (`azure/`)

| File | What it is |
|---|---|
| `manifest.yaml` | The package manifest: name, version, AKS only, one per cluster in namespace `aerolvm`. |
| `createUiDefinition.json` | The Azure portal form: the cluster, the extension name, the token Secret, the default isolation. |
| `mainTemplate.json` | The ARM template: one cluster extension. The `DONOTMODIFY` values are filled by Microsoft at publish. |
| `values-azure.yaml` | Every image under `global.azure.images`, which the chart reads (`aerolvm.image`). |
| `build.sh` | Lays the package out in `build/`, fills each image's amd64 digest, and runs Microsoft's `cpa verify`. |

`./azure/build.sh v0.7.3` passed `cpa verify` 1.3.63 on 2026-11-13:
manifest, Helm chart and package with no failures. One sub-check,
`arm-ttk` (the ARM template linter), crashed under emulation on an ARM
laptop; run `build.sh` on an amd64 machine to get its answer.

Your steps:

1. In Partner Center, create an Azure Container offer with a Kubernetes
   application plan.
2. Fill in `publisher` and `registryServer` in `manifest.yaml` (your ACR,
   in the same Entra tenant as Partner Center). Give the Microsoft service
   principal `32597670-3e15-4def-8851-614ff48c1efa` the `acrpull` role on
   it, and register the `Microsoft.PartnerCenterIngestion` provider on its
   subscription.
3. Run `build.sh <tag>`, then `cpa buildbundle` in `build/` to upload.
4. Attach the bundle to the plan and submit.

Rules Microsoft states that matter here: amd64 images only (`build.sh`
picks them), every image named in the chart's values, no images downloaded
at runtime by the app itself (a sandbox's own image is the customer's
workload, not the app's: say so in the listing), and images free of known
vulnerabilities.
