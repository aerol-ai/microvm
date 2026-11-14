package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"
)

// The chart's CRDs, which the operator's generated ones match
// (api/v1alpha1 TestChartCRDsMatch).
const crdDir = "../../../charts/aerolvm/crds"

func readCRD(t *testing.T, file string) apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(crdDir, file))
	if err != nil {
		t.Fatal(err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	return crd
}

// stale is crd as an older chart installed it: one field less in its
// schema, an older generator, and a label of the cluster's own.
func stale(crd apiextensionsv1.CustomResourceDefinition) *apiextensionsv1.CustomResourceDefinition {
	old := crd.DeepCopy()
	props := old.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["status"].Properties
	delete(props, "poolDecommission")
	old.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["status"] = apiextensionsv1.JSONSchemaProps{Type: "object", Properties: props}
	old.Annotations = map[string]string{"controller-gen.kubebuilder.io/version": "v0.1.0"}
	old.Labels = map[string]string{"kept": "yes"}
	return old
}

// A helm upgrade's hook brings an older CRD to the chart's: the field a
// newer operator writes is in its schema again, and what the cluster added
// to its metadata stays.
func TestApplyCRDsUpdatesInPlace(t *testing.T) {
	clusters := readCRD(t, "aerolvm.io_aerolclusters.yaml")
	nodes := readCRD(t, "aerolvm.io_aerolnodes.yaml")
	if _, ok := clusters.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["status"].Properties["poolDecommission"]; !ok {
		t.Fatal("the chart's AerolCluster CRD has no status.poolDecommission to restore")
	}
	c := fake.NewClientBuilder().WithScheme(crdScheme()).WithObjects(stale(clusters), stale(nodes)).Build()
	var out bytes.Buffer
	if err := applyCRDs(context.Background(), c, crdDir, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "updated aerolclusters.aerolvm.io\nupdated aerolnodes.aerolvm.io\n" {
		t.Fatalf("output = %q", got)
	}
	var have apiextensionsv1.CustomResourceDefinition
	if err := c.Get(context.Background(), client.ObjectKey{Name: clusters.Name}, &have); err != nil {
		t.Fatal(err)
	}
	if _, ok := have.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["status"].Properties["poolDecommission"]; !ok {
		t.Fatal("status.poolDecommission is still missing from the cluster's CRD")
	}
	if have.Annotations["controller-gen.kubebuilder.io/version"] != clusters.Annotations["controller-gen.kubebuilder.io/version"] || have.Labels["kept"] != "yes" {
		t.Fatalf("metadata = %v %v", have.Annotations, have.Labels)
	}
	// Again: nothing new, and nothing fails.
	if err := applyCRDs(context.Background(), c, crdDir, &out); err != nil {
		t.Fatal(err)
	}
}

// A CRD not on the cluster is skipped, never made: the hook's role cannot
// create, and Argo CD runs the hook before its first sync made the CRDs.
func TestApplyCRDsSkipsAMissingCRD(t *testing.T) {
	nodes := readCRD(t, "aerolvm.io_aerolnodes.yaml")
	c := fake.NewClientBuilder().WithScheme(crdScheme()).WithObjects(stale(nodes)).Build()
	var out bytes.Buffer
	if err := applyCRDs(context.Background(), c, crdDir, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "aerolclusters.aerolvm.io is not installed yet; skipped") || !strings.Contains(got, "updated aerolnodes.aerolvm.io") {
		t.Fatalf("output = %q", got)
	}
	var list apiextensionsv1.CustomResourceDefinitionList
	if err := c.List(context.Background(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("CRDs on the cluster: %d, %v", len(list.Items), err)
	}
}

func TestApplyCRDsRefuses(t *testing.T) {
	write := func(t *testing.T, files map[string]string) string {
		t.Helper()
		dir := t.TempDir()
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	good, err := os.ReadFile(filepath.Join(crdDir, "aerolvm.io_aerolnodes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	other := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: widgets.example.com}\nspec: {group: example.com}\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no files", map[string]string{"README.md": "x"}, "no CRD files"},
		{"not YAML", map[string]string{"a.yaml": "{"}, "a.yaml"},
		{"not a CRD", map[string]string{"a.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"}, "not an aerolvm.io CustomResourceDefinition"},
		// Another group's CRD in the folder: nothing is written, even
		// AerolVM's own.
		{"another group's CRD", map[string]string{"a.yaml": string(good), "b.yaml": other}, "not an aerolvm.io CustomResourceDefinition"},
	} {
		nodes := readCRD(t, "aerolvm.io_aerolnodes.yaml")
		c := fake.NewClientBuilder().WithScheme(crdScheme()).WithObjects(stale(nodes)).Build()
		err := applyCRDs(context.Background(), c, write(t, tc.files), &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
		var have apiextensionsv1.CustomResourceDefinition
		if err := c.Get(context.Background(), client.ObjectKey{Name: nodes.Name}, &have); err != nil || have.Labels["kept"] != "yes" || have.Annotations["controller-gen.kubebuilder.io/version"] != "v0.1.0" {
			t.Errorf("%s: the CRD changed: %v %v", tc.name, have.Annotations, err)
		}
	}
	// An update the API server refuses fails the hook, and so the upgrade.
	nodes := readCRD(t, "aerolvm.io_aerolnodes.yaml")
	c := fake.NewClientBuilder().WithScheme(crdScheme()).WithObjects(stale(nodes)).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
			return errors.New("forbidden")
		},
	}).Build()
	if err := applyCRDs(context.Background(), c, write(t, map[string]string{"a.yaml": string(good)}), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "update aerolnodes.aerolvm.io: forbidden") {
		t.Fatalf("a refused update: %v", err)
	}
}

// --apply-crds is a one-shot: no namespace needed, no manager started.
func TestRunApplyCRDs(t *testing.T) {
	if o, err := parse([]string{"--apply-crds", crdDir}); err != nil || o.applyCRDs != crdDir {
		t.Fatalf("--apply-crds without a namespace: %+v %v", o, err)
	}
	nodes := readCRD(t, "aerolvm.io_aerolnodes.yaml")
	c := fake.NewClientBuilder().WithScheme(crdScheme()).WithObjects(stale(nodes)).Build()
	was := newCRDClient
	t.Cleanup(func() { newCRDClient = was })
	newCRDClient = func() (client.Client, error) { return c, nil }
	if err := run([]string{"--apply-crds", crdDir}); err != nil {
		t.Fatal(err)
	}
	var have apiextensionsv1.CustomResourceDefinition
	if err := c.Get(context.Background(), client.ObjectKey{Name: nodes.Name}, &have); err != nil || have.Annotations["controller-gen.kubebuilder.io/version"] == "v0.1.0" {
		t.Fatalf("not updated: %v %v", have.Annotations, err)
	}
	newCRDClient = func() (client.Client, error) { return nil, errors.New("no kubeconfig") }
	if err := run([]string{"--apply-crds", crdDir}); err == nil || err.Error() != "no kubeconfig" {
		t.Fatalf("a client that cannot be made: %v", err)
	}
}

// The chart's hook, as Helm renders it (CI points AEROLVM_CHART_CRD_UPGRADE
// at templates/crd-upgrade.yaml rendered in cluster mode; without it the
// test skips): every object is a pre-upgrade hook removed once it worked,
// the role may only get and update AerolVM's own CRDs, the ConfigMap holds
// exactly the chart's CRD files, and the Job runs this command on them.
func TestChartCRDUpgradeHook(t *testing.T) {
	path := os.Getenv("AEROLVM_CHART_CRD_UPGRADE")
	if path == "" {
		t.Skip("AEROLVM_CHART_CRD_UPGRADE not set: no rendered chart to check")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(crdDir, "*.yaml"))
	var names []string
	for _, f := range files {
		names = append(names, readCRD(t, filepath.Base(f)).Name)
	}
	slices.Sort(names)
	seen := map[string]bool{}
	for _, doc := range strings.Split(string(raw), "\n---") {
		var meta struct {
			Kind     string            `json:"kind"`
			Metadata metav1.ObjectMeta `json:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind == "" {
			continue
		}
		seen[meta.Kind] = true
		a := meta.Metadata.Annotations
		if a["helm.sh/hook"] != "pre-upgrade" || a["helm.sh/hook-delete-policy"] != "before-hook-creation,hook-succeeded" {
			t.Errorf("%s %s: hook annotations %v", meta.Kind, meta.Metadata.Name, a)
		}
		switch meta.Kind {
		case "ClusterRole":
			var r rbacv1.ClusterRole
			if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
				t.Fatal(err)
			}
			if len(r.Rules) != 1 {
				t.Fatalf("ClusterRole rules = %+v", r.Rules)
			}
			rule := r.Rules[0]
			got := slices.Sorted(slices.Values(rule.ResourceNames))
			if !slices.Equal(rule.APIGroups, []string{"apiextensions.k8s.io"}) || !slices.Equal(rule.Resources, []string{"customresourcedefinitions"}) ||
				!slices.Equal(slices.Sorted(slices.Values(rule.Verbs)), []string{"get", "update"}) || !slices.Equal(got, names) {
				t.Errorf("ClusterRole rule = %+v, want get and update on %v only", rule, names)
			}
		case "ConfigMap":
			var cm corev1.ConfigMap
			if err := yaml.Unmarshal([]byte(doc), &cm); err != nil {
				t.Fatal(err)
			}
			if len(cm.Data) != len(files) {
				t.Errorf("ConfigMap holds %d files, the chart has %d", len(cm.Data), len(files))
			}
			// Parsed, not byte for byte: a YAML block drops a file's
			// trailing blanks.
			for _, f := range files {
				var got apiextensionsv1.CustomResourceDefinition
				if err := yaml.Unmarshal([]byte(cm.Data[filepath.Base(f)]), &got); err != nil {
					t.Fatalf("ConfigMap's %s: %v", filepath.Base(f), err)
				}
				if !reflect.DeepEqual(got, readCRD(t, filepath.Base(f))) {
					t.Errorf("ConfigMap's %s differs from the chart's", filepath.Base(f))
				}
			}
		case "Job":
			var j batchv1.Job
			if err := yaml.Unmarshal([]byte(doc), &j); err != nil {
				t.Fatal(err)
			}
			if w := a["helm.sh/hook-weight"]; w != "0" {
				t.Errorf("the Job's hook weight %q runs it before its role", w)
			}
			ctr := j.Spec.Template.Spec.Containers[0]
			if !strings.Contains(ctr.Image, "/aerolvm-operator:") || !slices.Contains(ctr.Args, "--apply-crds=/crds") {
				t.Errorf("Job container = %s %v", ctr.Image, ctr.Args)
			}
			if sc := ctr.SecurityContext; sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				t.Errorf("Job container security context = %+v", sc)
			}
		}
	}
	for _, k := range []string{"ServiceAccount", "ClusterRole", "ClusterRoleBinding", "ConfigMap", "Job"} {
		if !seen[k] {
			t.Errorf("the hook renders no %s", k)
		}
	}
}
