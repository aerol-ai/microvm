package safety

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd"
)

// The root helper runs no program through a folder a merged /usr makes a
// link (rootd.CheckRootProgramPath). Terraform cannot see a node and Ansible
// checks before it changes one, so both refuse those folders by name: each
// list must be the helper's, so none of the three takes a path another
// refuses. terraform_privilege_mode_test.go and
// ansible_privilege_mode_test.go run each rendered path through the
// helper's rule; this keeps the lists themselves in step.
func TestSplitLinkFoldersMatchTheHelper(t *testing.T) {
	want := rootd.MergedUsrLinks()
	quoted := regexp.MustCompile(`"([^"]+)"`)
	tf := regexp.MustCompile(`(?m)^\s+split_merged_usr_links\s+=\s+\[(.*)\]$`).FindStringSubmatch(readRepoFile(t, "Terraform", "privilege_mode.tf"))
	if tf == nil {
		t.Fatal("Terraform/privilege_mode.tf has no split_merged_usr_links")
	}
	var got []string
	for _, m := range quoted.FindAllStringSubmatch(tf[1], -1) {
		got = append(got, m[1])
	}
	if !slices.Equal(got, want) {
		t.Errorf("Terraform refuses %v, the root helper %v", got, want)
	}
	an := regexp.MustCompile(`(?m)^\s+sandboxd_split_merged_usr_links:\s+\[(.*)\]$`).FindStringSubmatch(readRepoFile(t, privilegeChecks))
	if an == nil {
		t.Fatalf("%s has no sandboxd_split_merged_usr_links", privilegeChecks)
	}
	got = nil
	for _, f := range strings.Split(an[1], ",") {
		got = append(got, strings.TrimSpace(f))
	}
	if !slices.Equal(got, want) {
		t.Errorf("Ansible refuses %v, the root helper %v", got, want)
	}
	// Each is a folder the helper's rule refuses a program under.
	for _, l := range want {
		if err := rootd.CheckRootProgramPath(l+"/x", nil); err == nil {
			t.Errorf("the root helper takes a program under %s", l)
		}
	}
}
