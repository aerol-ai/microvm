package cluster

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/hashicorp/memberlist"
)

// TestBuildVersionGossipRoundTrip: a node built with newGossipDelegate
// gossips its build as "bv", and a peer decodes it into Member.Version.
func TestBuildVersionGossipRoundTrip(t *testing.T) {
	d := newGossipDelegate("n1", "", "http://n1:21212", "", "n1:7000", "https://n1:7002", config.NodeRoleWorker, "", nil)
	enc := d.NodeMeta(memberlist.MetaMaxSize)
	if !strings.Contains(string(enc), `"bv":"`+version.Version+`"`) {
		t.Fatalf("meta = %s, want bv %q", enc, version.Version)
	}
	m := memberFromMemberlistNode(&memberlist.Node{Name: "n1", State: memberlist.StateAlive, Meta: enc})
	if m.Version != version.Version {
		t.Fatalf("decoded version = %q, want %q", m.Version, version.Version)
	}
	g := &gossipNode{delegate: d}
	if self := g.selfMember(); self.Version != version.Version {
		t.Fatalf("self version = %q", self.Version)
	}
}

// An older peer sends no bv: it reads as "", never as an error, and a meta
// built without a version is byte for byte what older builds gossip.
func TestBuildVersionOlderPeerReadsEmpty(t *testing.T) {
	old, err := json.Marshal(nodeMeta{NodeID: "old", APIURL: "http://old", RaftAddr: "old:7000", Role: config.NodeRoleServer, FSMOpsVersion: 3})
	if err != nil {
		t.Fatal(err)
	}
	m := memberFromMemberlistNode(&memberlist.Node{Name: "old", State: memberlist.StateAlive, Meta: old})
	if m.Version != "" || m.RaftAddr != "old:7000" || m.FSMOpsVersion != 3 {
		t.Fatalf("older peer decoded as %+v", m)
	}
	d := &gossipDelegate{nodeID: "x", apiURL: "http://x"}
	d.refreshMeta()
	if strings.Contains(string(d.encoded), `"bv"`) {
		t.Fatalf("a delegate without a build version gossips bv: %s", d.encoded)
	}
}

// TestNodeMetaWithBuildVersionFitsMetaSize is the 512-byte trap again, with
// bv: the largest realistic meta (63-character DNS labels everywhere, a long
// pre-release version, host PAT scope) fits memberlist's MetaMaxSize, and on
// whichever tier it lands it keeps RaftAddr, fv and the version.
func TestNodeMetaWithBuildVersionFitsMetaSize(t *testing.T) {
	label := strings.Repeat("n", 63)
	d := &gossipDelegate{
		nodeID:        label,
		nodeName:      label,
		apiURL:        "https://" + label + ".example.com:21212",
		dataPlaneHost: label + ".example.com",
		raftAddr:      "10.255.255.255:7000",
		internalURL:   "https://" + label + ".example.com:7002",
		role:          config.NodeRoleServer,
		publicHost:    label + ".example.com",
		buildVersion:  "v10.20.30-rc.10+g0123456789ab-dirty",
	}
	d.patScope = "host"
	d.refreshMeta()
	enc := d.NodeMeta(memberlist.MetaMaxSize)
	if len(enc) > memberlist.MetaMaxSize {
		t.Fatalf("meta is %d bytes", len(enc))
	}
	var meta nodeMeta
	if err := json.Unmarshal(enc, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.RaftAddr == "" || meta.FSMOpsVersion != fsmOpsVersion || meta.BuildVersion != d.buildVersion || meta.InternalURL == "" {
		t.Fatalf("decoded meta lost RaftAddr, fv, InternalURL or bv: %+v (%d bytes, full meta %d bytes)", meta, len(enc), len(d.encoded))
	}
}

// Past every realistic size, the version goes before Raft identity does.
func TestNodeMetaDropsBuildVersionBeforeRaftAddr(t *testing.T) {
	huge := strings.Repeat("h", 300)
	d := &gossipDelegate{
		nodeID:       "n1",
		apiURL:       "https://" + huge,
		raftAddr:     "10.0.0.1:7000",
		internalURL:  "https://" + huge,
		role:         config.NodeRoleServer,
		buildVersion: strings.Repeat("v", 200),
	}
	d.refreshMeta()
	var meta nodeMeta
	if err := json.Unmarshal(d.NodeMeta(memberlist.MetaMaxSize), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.RaftAddr != "10.0.0.1:7000" || meta.BuildVersion != "" {
		t.Fatalf("fallback = %+v, want RaftAddr kept and bv dropped", meta)
	}
}
