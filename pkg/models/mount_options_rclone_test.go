package models

import (
	"slices"
	"strings"
	"testing"
)

// rclone runs as root on the host, and its source and rclone_conf choose a
// backend and that backend's options. The local backend serves a host
// directory into the sandbox, and an option such as sftp's ssh runs a
// command, so both forms (the source's connection string and every
// rclone_conf section) are held to an allow list of remote-storage backends
// and a refusal list of options.
func TestValidateToolOptionsRclone(t *testing.T) {
	// env_auth = false is what rclone config writes by default.
	const s3conf = "[remote]\ntype = s3\nprovider = AWS\nenv_auth = false\naccess_key_id = AK\nsecret_access_key = SK\n"
	rc := func(source, conf string) MountSpec {
		m := MountSpec{Type: MountTypeRclone, Source: source, Target: "/d"}
		if conf != "" {
			m.Credentials = map[string]string{"rclone_conf": conf}
		}
		return m
	}

	accepted := []struct {
		name string
		m    MountSpec
	}{
		{"configured s3 remote", rc("remote:bucket/prefix", s3conf)},
		{"remote override", rc("remote,region=eu-west-1:bucket", s3conf)},
		{"on the fly s3", rc(":s3,provider=AWS,env_auth=false:bucket", "")},
		{"on the fly gcs prefix", rc(":gcs:bucket", "")},
		{"quoted override value", rc(`remote,endpoint="https://s3.example:9000":bucket`, s3conf)},
		{"sftp with inline key", rc("box:data", "[box]\ntype = sftp\nhost = files.example\nuser = me\nkey_pem = -----BEGIN KEY-----\n")},
		{"gcs by its name", rc("g:b", "[g]\ntype = google cloud storage\nservice_account_credentials = {}\n")},
		{"drive with token", rc("d:", "[d]\ntype = drive\ntoken = {\"access_token\":\"x\"}\n")},
		{"colon separator and comments", rc("remote:b", "# made by rclone config\n; another comment\n[remote]\ntype: s3\n\nregion: us-east-1\n")},
		{"crypt over a section", rc("secret:", s3conf+"[secret]\ntype = crypt\nremote = remote:bucket/enc\npassword = obscured\n")},
		{"alias chain", rc("a:", s3conf+"[b]\ntype = crypt\nremote = remote:x\n[a]\ntype = alias\nremote = b:\n")},
		{"wrapper over on the fly backend", rc("c:", "[c]\ntype = chunker\nremote = :s3,provider=Minio:bucket\n")},
		{"unused second section", rc("remote:b", s3conf+"[web]\ntype = webdav\nurl = https://dav.example\n")},
	}
	for _, tc := range accepted {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := tc.m.Validate("/usr/local/bin/toolboxd"); err != nil {
				t.Fatalf("Validate = %v", err)
			}
			if err := tc.m.ValidateToolOptions(); err != nil {
				t.Fatalf("ValidateToolOptions = %v, want accepted", err)
			}
		})
	}

	refused := []struct {
		name string
		m    MountSpec
		want string
	}{
		// The source: a backend made on the fly, its overrides, and a
		// remote the config does not define.
		{"on the fly local", rc(":local:/etc", "#"), `rclone source uses rclone backend "local", which is not allowed`},
		{"on the fly local, no config", rc(":local:/etc", ""), `backend "local"`},
		{"on the fly alias", rc(":alias,remote=/etc:", ""), `backend "alias"`},
		{"on the fly union", rc(":union,upstreams=/etc:", ""), `backend "union"`},
		{"on the fly unknown", rc(":futurefs:x", ""), `backend "futurefs"`},
		{"source key_file", rc(":sftp,host=h,key_file=/etc/shadow:p", ""), `rclone source parameter "key_file" is not allowed: it names a file or folder on the server`},
		{"source ssh", rc(":sftp,host=h,ssh='sh -c id':p", ""), `rclone source parameter "ssh" is not allowed: it runs a command`},
		{"source password_command", rc("remote,password_command=id:b", s3conf), `"password_command" is not allowed: it runs a command`},
		{"source global option", rc("remote,global.ca_cert=x:b", s3conf), `"global.ca_cert" is not allowed: it sets one of rclone's global options`},
		{"source override option", rc("remote,override.ca_cert=x:b", s3conf), "global options"},
		{"source type swap", rc("remote,type=local:/etc", s3conf), `rclone source parameter "type" is not allowed`},
		{"source remote swap", rc("w,remote=/etc:", s3conf+"[w]\ntype = alias\nremote = remote:b\n"), `rclone source parameter "remote" is not allowed`},
		{"source profile", rc("remote,profile=default:b", s3conf), `"profile" is not allowed: it reads the server's own credential files`},
		{"source remote not in config", rc("other:b", s3conf), `rclone source remote "other" is not a section`},
		{"source with no config", rc("remote:b", ""), `rclone source remote "remote" is not a section`},
		// rclone_conf: every section, whether the source names it or not.
		{"conf local", rc("store:/etc", "[store]\ntype = local\n"), `section "store" uses rclone backend "local"`},
		{"conf local unused", rc("remote:b", s3conf+"[x]\ntype = local\n"), `section "x" uses rclone backend "local"`},
		{"conf union", rc("u:", "[u]\ntype = union\nupstreams = /etc remote:b\n"), `backend "union"`},
		{"conf cache", rc("c:", "[c]\ntype = cache\nremote = remote:b\n"), `backend "cache"`},
		{"conf hdfs", rc("h:", "[h]\ntype = hdfs\nnamenode = nn:8020\n"), `backend "hdfs"`},
		{"conf type case", rc("remote:b", "[remote]\ntype = Local\n"), `backend "local"`},
		{"conf no type", rc("remote:b", "[remote]\nprovider = AWS\n"), `section "remote" has no type`},
		{"conf sftp ssh", rc("box:d", "[box]\ntype = sftp\nssh = sh -c 'id > /tmp/x'\n"), `section "box" option "ssh" is not allowed: it runs a command`},
		{"conf sftp ssh colon form", rc("box:d", "[box]\ntype = sftp\nssh: sh -c id\n"), `option "ssh" is not allowed`},
		{"conf sftp key_file", rc("box:d", "[box]\ntype = sftp\nkey_file = /root/.ssh/id_ed25519\n"), `option "key_file" is not allowed: it names a file or folder on the server`},
		{"conf sftp pubkey_file", rc("box:d", "[box]\ntype = sftp\npubkey_file = /x\n"), `option "pubkey_file"`},
		{"conf sftp known_hosts_file", rc("box:d", "[box]\ntype = sftp\nknown_hosts_file = /x\n"), `option "known_hosts_file"`},
		{"conf sftp agent", rc("box:d", "[box]\ntype = sftp\nkey_use_agent = true\n"), `option "key_use_agent" is not allowed: it uses the server's ssh agent`},
		{"conf sftp server_command", rc("box:d", "[box]\ntype = sftp\nserver_command = /x\n"), `option "server_command" is not allowed: it runs a command`},
		{"conf webdav bearer command", rc("w:", "[w]\ntype = webdav\nbearer_token_command = id\n"), `option "bearer_token_command"`},
		{"conf drive service account file", rc("d:", "[d]\ntype = drive\nservice_account_file = /etc/gcp.json\n"), `option "service_account_file"`},
		{"conf s3 shared credentials", rc("remote:b", "[remote]\ntype = s3\nshared_credentials_file = /root/.aws/credentials\n"), `option "shared_credentials_file"`},
		{"conf dash key", rc("remote:b", "[remote]\ntype = s3\nkey-file = /x\n"), `option "key-file"`},
		{"conf global option", rc("remote:b", "[remote]\ntype = s3\nglobal.ca_cert = /x\n"), `option "global.ca_cert"`},
		{"conf dir option", rc("remote:b", "[remote]\ntype = s3\ncache_dir = /x\n"), `option "cache_dir"`},
		{"conf path option", rc("remote:b", "[remote]\ntype = s3\nchunk_path = /x\n"), `option "chunk_path"`},
		{"wrapper over local path", rc("a:", "[a]\ntype = alias\nremote = /etc\n"), `section "a" (alias) must wrap a remote:path`},
		{"wrapper over on the fly local", rc("a:", "[a]\ntype = alias\nremote = :local:/etc\n"), `section "a" remote uses rclone backend "local"`},
		{"wrapper over missing section", rc("a:", "[a]\ntype = crypt\nremote = gone:x\n"), `wraps remote "gone", which is not a section`},
		{"wrapper over local section", rc("a:", "[l]\ntype = local\n[a]\ntype = alias\nremote = l:/etc\n"), `section "l" uses rclone backend "local"`},
		{"wrapper remote param", rc("a:", s3conf+"[a]\ntype = alias\nremote = remote,key_file=/x:b\n"), `remote parameter "key_file" is not allowed`},
		// rclone_conf that cannot be read for certain.
		{"conf encrypted", rc("remote:b", "# Encrypted rclone configuration File\n\nRCLONE_ENCRYPT_V0:\nAAAA\n"), "line 3 is outside any [remote] section"},
		{"conf line before section", rc("remote:b", "type = local\n[remote]\ntype = s3\n"), "line 1 is outside any [remote] section"},
		{"conf bad header", rc("remote:b", "[remote\ntype = s3\n"), "line 1 is not a valid [remote] header"},
		{"conf bad header name", rc("remote:b", "[a/b]\ntype = s3\n"), "line 1 is not a valid [remote] header"},
		{"conf duplicate section", rc("remote:b", s3conf+"[remote]\ntype = local\n"), `section "remote" appears twice`},
		{"conf duplicate key", rc("remote:b", "[remote]\ntype = s3\ntype = local\n"), `section "remote" sets "type" twice`},
		{"conf not key value", rc("remote:b", "[remote]\ntype = s3\njust words\n"), "line 3 is not key = value"},
		{"conf odd key", rc("remote:b", "[remote]\ntype = s3\nmy key = x\n"), "line 3 has a key rclone would not read"},
		{"conf multi-line value", rc("remote:b", "[remote]\ntype = s3\nssh = \"\"\"\nid\n\"\"\"\n"), "line 3 starts a multi-line value"},
	}
	for _, tc := range refused {
		t.Run("refuse/"+tc.name, func(t *testing.T) {
			if err := tc.m.Validate("/usr/local/bin/toolboxd"); err != nil {
				t.Fatalf("Validate = %v, want the shape accepted", err)
			}
			err := tc.m.ValidateToolOptions()
			if err == nil {
				t.Fatalf("ValidateToolOptions(%q) accepted", tc.m.Source)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// What rclone reads as a local path never passes as a source: no remote
// part, or one rclone would not read as a remote name.
func TestValidateRcloneSourceShape(t *testing.T) {
	for _, src := range []string{"data", "../etc", "./x:y", "/var/data", "a/b:c", "a b:c", ":", "::x", "remote,:x", "remote,=v:x", `remote,k="unterminated:x`, "rem\\ote:x"} {
		m := MountSpec{Type: MountTypeRclone, Source: src, Target: "/d"}
		if err := m.Validate(""); err == nil || !strings.Contains(err.Error(), "rclone source must be a configured remote") {
			t.Errorf("Validate(%q) = %v, want the local-path refusal", src, err)
		}
		if err := validateRclone(src, "[remote]\ntype = s3\n", MountToolPolicy{}); err == nil || !strings.Contains(err.Error(), "rclone source must look like remote:path") {
			t.Errorf("validateRclone(%q) = %v", src, err)
		}
	}
	for src, want := range map[string]rcloneRemote{
		"remote:path":                   {name: "remote"},
		":s3,provider=AWS:bucket":       {name: "s3", onTheFly: true, params: []rcloneParam{{"provider", "AWS", true}}},
		`r,a="x:y,z",b='q''s':p`:        {name: "r", params: []rcloneParam{{"a", `"x:y,z"`, true}, {"b", `'q''s'`, true}}},
		"r,flag:p":                      {name: "r", params: []rcloneParam{{"flag", "", false}}},
		"  name.with+at@-dash_1:x/y:z ": {name: "name.with+at@-dash_1"},
	} {
		got, ok := parseRcloneRemote(src)
		if !ok || got.name != want.name || got.onTheFly != want.onTheFly || !slices.Equal(got.params, want.params) {
			t.Errorf("parseRcloneRemote(%q) = %+v %v, want %+v", src, got, ok, want)
		}
	}
}

// The lists themselves: no backend that reaches the host is allowed, and
// the option refusals name every kind.
func TestRcloneListsLeaveOutHostBackends(t *testing.T) {
	for _, b := range []string{"local", "union", "combine", "cache", "hdfs", "memory", "alias", "crypt"} {
		for _, allowed := range rcloneStorageBackends {
			if allowed == b {
				t.Errorf("backend %q is a storage backend", b)
			}
		}
	}
	for name, want := range map[string]string{
		"ssh": "runs a command", "md5sum_command": "runs a command", "Password-Command": "runs a command",
		"key_file": "names a file", "db_path": "names a file", "temp_dir": "names a file",
		"override.ca_cert": "global options", "key_use_agent": "ssh agent", "profile": "credential files",
		"key_pem": "", "token": "", "env_auth": "", "host": "", "remote": "", "type": "",
	} {
		got := rcloneOptionRefusal(name)
		if want == "" && got != "" || want != "" && !strings.Contains(got, want) {
			t.Errorf("rcloneOptionRefusal(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestRcloneNodeCredentials: an option that makes rclone take the node's
// own cloud identity (its environment, instance metadata, managed identity
// or Azure CLI login) is refused in rclone_conf and in the source, unless
// the operator allows node credentials. On the base these passed: a
// tenant's mount could act as the node's IAM role.
func TestRcloneNodeCredentials(t *testing.T) {
	rc := func(source, conf string) MountSpec {
		m := MountSpec{Type: MountTypeRclone, Source: source, Target: "/d"}
		if conf != "" {
			m.Credentials = map[string]string{"rclone_conf": conf}
		}
		return m
	}
	nodeCreds := []struct {
		name string
		m    MountSpec
		want string
	}{
		{"s3 env_auth", rc("r:b", "[r]\ntype = s3\nprovider = AWS\nenv_auth = true\n"), `option "env_auth"`},
		{"s3 env_auth with no value", rc("r:b", "[r]\ntype = s3\nenv_auth\n"), "is not key = value"},
		{"gcs env_auth", rc("g:b", "[g]\ntype = gcs\nenv_auth = 1\n"), `option "env_auth"`},
		{"azure managed identity", rc("a:c", "[a]\ntype = azureblob\naccount = acct\nuse_msi = true\n"), `option "use_msi"`},
		{"azure managed identity by id", rc("a:c", "[a]\ntype = azureblob\nmsi_client_id = 0000\n"), `option "msi_client_id"`},
		{"azure cli login", rc("a:c", "[a]\ntype = azureblob\naccount = acct\nuse_az = true\n"), `option "use_az"`},
		{"oracle instance principal", rc("o:b", "[o]\ntype = oracleobjectstorage\nprovider = instance_principal_auth\n"), `option "provider"`},
		{"swift environment", rc("s:c", "[s]\ntype = swift\nenv_auth = true\n"), `option "env_auth"`},
		{"on the fly env_auth", rc(":s3,provider=AWS,env_auth=true:bucket", ""), `parameter "env_auth"`},
		{"on the fly env_auth, no value", rc(":s3,env_auth:bucket", ""), `parameter "env_auth"`},
		{"override on a configured remote", rc("r,env_auth=true:b", "[r]\ntype = s3\n"), `parameter "env_auth"`},
		{"wrapper over an on the fly env_auth", rc("c:", "[c]\ntype = chunker\nremote = :s3,env_auth='true':bucket\n"), `remote parameter "env_auth"`},
	}
	for _, tc := range nodeCreds {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.ValidateToolOptions()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateToolOptions = %v, want %q", err, tc.want)
			}
			if strings.Contains(tc.want, "key = value") {
				return
			}
			if !strings.Contains(err.Error(), "SB_MOUNTS_ALLOW_NODE_CREDENTIALS") {
				t.Fatalf("the refusal does not name the setting: %v", err)
			}
			// A running mount is torn down too: the running tool keeps
			// acting as the node.
			if err := tc.m.ValidateRunningToolOptions(); err == nil {
				t.Fatal("a running mount kept the node's identity")
			}
			// The operator's setting allows it.
			allowed := MountToolPolicy{NodeCredentials: true}
			if err := tc.m.ValidateToolOptionsFor(allowed); err != nil {
				t.Fatalf("allowed by the operator: %v", err)
			}
			if err := tc.m.ValidateRunningToolOptionsFor(allowed); err != nil {
				t.Fatalf("running, allowed by the operator: %v", err)
			}
		})
	}
	// A switch set off takes nothing from the node.
	for _, conf := range []string{
		"[r]\ntype = s3\nenv_auth = false\n", "[r]\ntype = s3\nenv_auth = 0\n", "[r]\ntype = azureblob\nuse_msi = False\n",
		"[r]\ntype = s3\nprovider = Minio\n", "[r]\ntype = azureblob\nmsi_client_id =\n",
	} {
		m := rc("r:b", conf)
		if err := m.ValidateToolOptions(); err != nil {
			t.Errorf("%q: %v", conf, err)
		}
	}
	if m := rc(":s3,env_auth=false:bucket", ""); m.ValidateToolOptions() != nil {
		t.Errorf("on the fly env_auth=false: %v", m.ValidateToolOptions())
	}
}
