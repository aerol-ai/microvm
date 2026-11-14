package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

// applyCRDs brings AerolVM's CustomResourceDefinitions on the cluster up to
// the YAML files in dir, then the command exits. Helm installs a chart's
// crds/ on the first install and never updates them, so a `helm upgrade`
// left a cluster on its first CRDs, and the API server dropped every field
// added since (status.poolDecommission, spec.servers.logStorage, ...). The
// chart runs this as a pre-upgrade hook Job (templates/crd-upgrade.yaml)
// whose role may only get and update these two CRDs.
//
// Each CRD's spec is replaced by the file's; its other metadata stays. A
// CRD that is not on the cluster is skipped, not made: the first install
// makes it, the role cannot create, and Argo CD runs this hook before its
// first sync has created anything. A rollback runs no pre-upgrade hook, so
// a newer CRD stays in place; its fields are additive.
func applyCRDs(ctx context.Context, c client.Client, dir string, out io.Writer) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no CRD files (*.yaml) in %s", dir)
	}
	// Every file is read and checked before anything is written: a bad
	// file leaves the cluster's CRDs as they were.
	want := make([]apiextensionsv1.CustomResourceDefinition, 0, len(files))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var crd apiextensionsv1.CustomResourceDefinition
		if err := yaml.Unmarshal(raw, &crd); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if crd.Kind != "CustomResourceDefinition" || crd.Spec.Group != v1.GroupVersion.Group || crd.Name == "" {
			return fmt.Errorf("%s: not an %s CustomResourceDefinition", f, v1.GroupVersion.Group)
		}
		want = append(want, crd)
	}
	for _, crd := range want {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var have apiextensionsv1.CustomResourceDefinition
			if err := c.Get(ctx, client.ObjectKey{Name: crd.Name}, &have); err != nil {
				return err
			}
			have.Spec = crd.Spec
			for k, v := range crd.Annotations {
				if have.Annotations == nil {
					have.Annotations = map[string]string{}
				}
				have.Annotations[k] = v
			}
			return c.Update(ctx, &have)
		})
		switch {
		case apierrors.IsNotFound(err):
			fmt.Fprintf(out, "%s is not installed yet; skipped (the install creates it)\n", crd.Name)
		case err != nil:
			return fmt.Errorf("update %s: %w", crd.Name, err)
		default:
			fmt.Fprintf(out, "updated %s\n", crd.Name)
		}
	}
	return nil
}

// crdScheme knows the CustomResourceDefinition type, for applyCRDs' client.
func crdScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(s); err != nil {
		panic(err)
	}
	return s
}
