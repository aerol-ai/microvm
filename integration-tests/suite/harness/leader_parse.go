package harness

import (
	"encoding/json"
	"strings"
)

// ParseLeaderJSON extracts the leader id from one node's /v1/cluster/leader
// body. Anything unparseable reads as "no leader": the callers poll, and a
// garbled capture (SSHRun merges stderr) must look like "not yet", never like
// a leader name that happens to be curl's error text.
func ParseLeaderJSON(body string) string {
	var resp struct {
		Leader string `json:"leader"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &resp); err != nil {
		return ""
	}
	return strings.TrimSpace(resp.Leader)
}
