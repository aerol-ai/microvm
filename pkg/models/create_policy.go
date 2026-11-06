package models

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrCreatePolicyDenied matches every refusal by the operator's create
// policy (SB_CREATE_POLICY_FILE). The API answers 403 with the code
// ErrorCodeCreatePolicyDenied: retrying the same request cannot succeed.
var ErrCreatePolicyDenied = errors.New("refused by this server's create policy")

// ErrorCodeCreatePolicyDenied is returned (403) for a create or resize the
// operator's create policy refuses. The message names the rule.
const ErrorCodeCreatePolicyDenied = "create_policy_denied"

// ErrorCodeCreatePolicyInvalid is returned (503) for every create and resize
// while the create policy file is set but did not load at boot: the limits
// are unknown, so the server fails closed until the file is fixed.
const ErrorCodeCreatePolicyInvalid = "create_policy_invalid"

// CreatePolicyError is one refusal, naming the policy rule that refused it so
// the caller (and the operator reading the log) knows which line of the file
// to look at. It lives here, not in the policy package, because the runtime
// drivers raise the require_non_root refusal after they read the image.
type CreatePolicyError struct {
	Rule   string
	Detail string
}

func (e *CreatePolicyError) Error() string {
	return fmt.Sprintf("create refused by policy rule %q: %s", e.Rule, e.Detail)
}

// Is makes every CreatePolicyError match ErrCreatePolicyDenied.
func (e *CreatePolicyError) Is(target error) bool { return target == ErrCreatePolicyDenied }

// CreatePolicyRuleRequireNonRoot names the rule CheckImageUserNonRoot
// enforces.
const CreatePolicyRuleRequireNonRoot = "require_non_root"

// CheckImageUserNonRoot holds an image's configured user (the USER line,
// as the image config reports it) to the require_non_root rule. Like
// Kubernetes' runAsNonRoot, only a numeric user id other than 0 passes: a
// name could map to uid 0 in the image's /etc/passwd, and reading that file
// would mean unpacking the image on the create path. An empty user is root,
// the runtime default.
func CheckImageUserNonRoot(image, user string) error {
	user = strings.TrimSpace(user)
	uid, _, _ := strings.Cut(user, ":")
	if uid == "" {
		return &CreatePolicyError{Rule: CreatePolicyRuleRequireNonRoot,
			Detail: fmt.Sprintf("image %q runs as root (no USER); build it with a numeric non-root USER, such as USER 1000", image)}
	}
	n, err := strconv.ParseUint(uid, 10, 32)
	if err != nil {
		return &CreatePolicyError{Rule: CreatePolicyRuleRequireNonRoot,
			Detail: fmt.Sprintf("image %q runs as user %q, a name the server cannot check without reading the image; use a numeric USER, such as USER 1000", image, user)}
	}
	if n == 0 {
		return &CreatePolicyError{Rule: CreatePolicyRuleRequireNonRoot,
			Detail: fmt.Sprintf("image %q runs as root (USER %s); build it with a numeric non-root USER, such as USER 1000", image, user)}
	}
	return nil
}
