//go:build linux

package egress

import (
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// nftCoverProdConn is newConn as the package builds it. useFakeNFT swaps the
// var, so it has to be taken before any test runs.
var nftCoverProdConn = newConn

var errNFTCover = errors.New("netlink refused")

// nftCoverKernel is a fake kernel holding an older egress table whose only
// set is fqdn_src, so EnsureLayout takes the carry-over path. Each fail
// field refuses one kind of request.
type nftCoverKernel struct {
	noTable    bool
	allSets    bool // the GETSET dump lists every current set instead
	elemKey    []byte
	failElems  bool
	failChains bool
	failBatch  bool
}

// nftCoverSetMsg describes an IPv4-keyed set, so the carry check finds it
// compatible with this version's fqdn_src.
func nftCoverSetMsg(name string) netlink.Message {
	ip := nftables.TypeIPAddr
	return nftGen([]netlink.Attribute{
		{Type: unix.NFTA_SET_NAME, Data: append([]byte(name), 0)},
		{Type: unix.NFTA_SET_KEY_TYPE, Data: binaryutil.BigEndian.PutUint32(ip.GetNFTMagic())},
	}, unix.NFT_MSG_NEWSET)
}

func nftCoverElemMsg(keyData []byte) netlink.Message {
	key := nltest.MustMarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_DATA_VALUE, Data: keyData}})
	elem := nltest.MustMarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_SET_ELEM_KEY, Data: key}})
	list := nltest.MustMarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_LIST_ELEM, Data: elem}})
	return nftGen([]netlink.Attribute{{Type: unix.NFTA_SET_ELEM_LIST_ELEMENTS, Data: list}}, unix.NFT_MSG_NEWSETELEM)
}

func (k nftCoverKernel) dial(req []netlink.Message) ([]netlink.Message, error) {
	if len(req) == 0 {
		return nil, io.EOF
	}
	if len(req) == 1 && req[0].Header.Flags&netlink.Dump != 0 {
		var msgs []netlink.Message
		switch nftOp(req[0]) {
		case unix.NFT_MSG_GETTABLE:
			if !k.noTable {
				msgs = append(msgs, nftGen([]netlink.Attribute{
					{Type: unix.NFTA_TABLE_NAME, Data: append([]byte(TableName), 0)},
				}, unix.NFT_MSG_NEWTABLE))
			}
		case unix.NFT_MSG_GETSET:
			if k.allSets {
				for _, d := range setDefs {
					msgs = append(msgs, nftCoverSetMsg(d.name))
				}
			} else {
				msgs = append(msgs, nftCoverSetMsg(SetFQDNSrc))
			}
		case unix.NFT_MSG_GETSETELEM:
			if k.failElems {
				return nil, errNFTCover
			}
			if k.elemKey != nil {
				msgs = append(msgs, nftCoverElemMsg(k.elemKey))
			}
		case unix.NFT_MSG_GETCHAIN:
			if k.failChains {
				return nil, errNFTCover
			}
		}
		if len(msgs) == 0 {
			return nil, io.EOF
		}
		return withDone(req[0], msgs), nil
	}
	if k.failBatch {
		return nil, errNFTCover
	}
	out := make([]netlink.Message, 0, len(req))
	for _, msg := range req {
		acks, err := nltest.Error(0, []netlink.Message{msg})
		if err != nil {
			return nil, err
		}
		out = append(out, acks...)
	}
	return out, nil
}

func useNFTCoverKernel(t *testing.T, k nftCoverKernel) {
	t.Helper()
	orig := newConn
	t.Cleanup(func() { newConn = orig })
	newConn = func() (*nftables.Conn, error) {
		return nftables.New(nftables.WithTestDial(k.dial))
	}
}

// nftCoverAnonymous makes the library refuse to queue writes to the named
// sets: it rejects an anonymous set before anything is sent, the one way
// to fail that step without a kernel. constant decides whether AddSet
// accepts the set too.
func nftCoverAnonymous(b *NFTBackend, constant bool, names ...string) {
	for _, name := range names {
		s := *b.sets[name]
		s.Anonymous, s.Constant, s.ID = true, constant, 1
		b.sets[name] = &s
	}
}

func TestNFTCoverProductionConn(t *testing.T) {
	// nftables.New without options does not dial, so this is safe
	// unprivileged.
	c, err := nftCoverProdConn()
	if err != nil || c == nil {
		t.Fatalf("production conn = %v %v", c, err)
	}
}

func TestNFTCoverEnsureLayoutCarry(t *testing.T) {
	cfg := LayoutConfig{DNSPort: 53054, ProxyPort: 15080, FlowSetSize: 64}
	src := netip.MustParseAddr("10.9.0.2")
	cases := []struct {
		name   string
		kernel nftCoverKernel
		anon   []string
		want   string // "" means success
	}{
		{"carried source", nftCoverKernel{elemKey: ip4(src)}, nil, ""},
		{"carried set unreadable", nftCoverKernel{failElems: true}, nil, "keeping the existing table"},
		// A short key decodes as no address, which can't be re-encoded.
		{"carried element undecodable", nftCoverKernel{elemKey: []byte{10, 9}}, nil, "without IPv4 source"},
		{"carried set refused", nftCoverKernel{elemKey: ip4(src)}, []string{SetFQDNSrc, SetBlockedSrc}, "carry"},
		{"commit refused", nftCoverKernel{noTable: true, failBatch: true}, nil, "create egress layout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useNFTCoverKernel(t, tc.kernel)
			b := NewNFTBackend()
			nftCoverAnonymous(b, true, tc.anon...)
			err := b.EnsureLayout(cfg)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("EnsureLayout = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNFTCoverCarriedElements(t *testing.T) {
	src := netip.MustParseAddr("10.9.0.2")
	k := nftCoverKernel{elemKey: ip4(src)}
	c, err := nftables.New(nftables.WithTestDial(k.dial))
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewNFTBackend().carriedElements(c)
	if err != nil {
		t.Fatal(err)
	}
	// The carried source comes back, and is blocked until Sync.
	if len(got[SetFQDNSrc]) != 1 || got[SetFQDNSrc][0].Src != src || len(got[SetBlockedSrc]) != 1 {
		t.Fatalf("carried = %+v", got)
	}
}

func TestNFTCoverQueueFailures(t *testing.T) {
	useFakeNFT(t, nftEmpty)
	src := netip.MustParseAddr("10.9.0.2")

	b := NewNFTBackend()
	nftCoverAnonymous(b, false, SetFQDNSrc)
	if err := b.EnsureLayout(LayoutConfig{DNSPort: 53054, ProxyPort: 15080}); err == nil || !strings.Contains(err.Error(), "add set "+SetFQDNSrc) {
		t.Fatalf("EnsureLayout with a refused set = %v", err)
	}
	if err := b.Apply([]Op{{Set: SetFQDNSrc, Elems: []Elem{{Src: src}}}}); err == nil || !strings.Contains(err.Error(), "queue "+SetFQDNSrc) {
		t.Fatalf("Apply to a refused set = %v", err)
	}
	if err := b.Replace(map[string][]Elem{SetFQDNSrc: {{Src: src}}}); err == nil || !strings.Contains(err.Error(), "queue "+SetFQDNSrc) {
		t.Fatalf("Replace of a refused set = %v", err)
	}
	if err := NewNFTBackend().Replace(map[string][]Elem{SetFQDNSrc: {{Src: netip.MustParseAddr("2001:db8::9")}}}); err == nil {
		t.Fatal("Replace accepted an IPv6 source")
	}
}

func TestNFTCoverCheckLayoutChainsUnreadable(t *testing.T) {
	useNFTCoverKernel(t, nftCoverKernel{allSets: true, failChains: true})
	if err := NewNFTBackend().CheckLayout(); !errors.Is(err, ErrLayoutMissing) {
		t.Fatalf("CheckLayout with unreadable chains = %v", err)
	}
}
