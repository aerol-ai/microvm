package api

import (
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// maxHintGroups caps how many groups a "no binding" message lists inline.
// The v1 body carries every group in `groups`; the message is for a person
// reading a terminal (the CLI's DR15 wording uses the same cap).
const maxHintGroups = 10

// noBindingMessage is the "no binding" 403 text (§5.5, D9): the caller's own
// display name, the issuer they signed in through and the groups their token
// carried, so they can tell their admin what is missing. Nothing in it
// comes from another principal or from the identity file's bindings.
func noBindingMessage(nb *controlplane.NoBindingError) string {
	who := "no role binding for " + nb.Name + " through issuer " + nb.Issuer
	switch {
	case nb.Overage:
		return who + ": group overage, the sign-in carried too many groups to list; bind on Entra app roles"
	case len(nb.Groups) == 0:
		return who + "; the sign-in carried no groups; ask your AerolVM admin to add a binding for your account"
	}
	shown := nb.Groups
	more := ""
	if len(shown) > maxHintGroups {
		more = " (and " + strconv.Itoa(len(shown)-maxHintGroups) + " more)"
		shown = shown[:maxHintGroups]
	}
	return who + "; the sign-in carried groups: " + strings.Join(shown, ", ") + more +
		"; ask your AerolVM admin to add a binding for one of them"
}
