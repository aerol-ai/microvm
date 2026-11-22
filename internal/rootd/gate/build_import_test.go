package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	contentapi "github.com/containerd/containerd/api/services/content/v1"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	leasesapi "github.com/containerd/containerd/api/services/leases/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// A rootless build's image reaches containerd as an OCI archive that the
// agent imports itself (internal/runtime/containerd ImportBuildArchive,
// plans/security-gaps-m1-m4.md PR 10b): content writes, labels, an image
// record and, like a pull, an unpack. These tests run that sequence with
// containerd's own client library through the gate. Nothing new is on the
// allowlist for it: the transfer service, which would read the archive as
// root, stays refused (TestUnlistedMethodsRefused).

// contentContainerd gives the fake a content store and an image store
// enough for the client's content writer, reader and label updates.
func contentContainerd(r *rig) map[digest.Digest][]byte {
	var mu sync.Mutex
	blobs := map[digest.Digest][]byte{}
	labels := map[digest.Digest]map[string]string{}
	pending := map[string]*bytes.Buffer{}
	one := func(m proto.Message) ([]proto.Message, error) { return []proto.Message{m}, nil }
	f := r.fake
	f.on("/containerd.services.leases.v1.Leases/Create", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		return one(&leasesapi.CreateResponse{Lease: &leasesapi.Lease{ID: q.(*leasesapi.CreateRequest).GetID()}})
	})
	f.on("/containerd.services.content.v1.Content/Write", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		w := q.(*contentapi.WriteContentRequest)
		mu.Lock()
		defer mu.Unlock()
		buf := pending[w.GetRef()]
		if buf == nil {
			buf = &bytes.Buffer{}
			pending[w.GetRef()] = buf
		}
		switch w.GetAction() {
		case contentapi.WriteAction_STAT:
			if _, ok := blobs[digest.Digest(w.GetExpected())]; ok {
				return nil, status.Error(codes.AlreadyExists, "content exists")
			}
			return one(&contentapi.WriteContentResponse{Action: w.GetAction(), Offset: int64(buf.Len()), Total: w.GetTotal()})
		case contentapi.WriteAction_WRITE:
			buf.Write(w.GetData())
			return one(&contentapi.WriteContentResponse{Action: w.GetAction(), Offset: int64(buf.Len())})
		default:
			buf.Write(w.GetData())
			d := digest.FromBytes(buf.Bytes())
			if exp := digest.Digest(w.GetExpected()); exp != "" && exp != d {
				return nil, status.Error(codes.FailedPrecondition, "unexpected commit digest")
			}
			blobs[d] = bytes.Clone(buf.Bytes())
			delete(pending, w.GetRef())
			return one(&contentapi.WriteContentResponse{Action: w.GetAction(), Offset: int64(len(blobs[d])), Digest: d.String()})
		}
	})
	info := func(d digest.Digest) *contentapi.Info {
		return &contentapi.Info{Digest: d.String(), Size: int64(len(blobs[d])), Labels: labels[d], CreatedAt: timestamppb.Now(), UpdatedAt: timestamppb.Now()}
	}
	f.on("/containerd.services.content.v1.Content/Info", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		d := digest.Digest(q.(*contentapi.InfoRequest).GetDigest())
		mu.Lock()
		defer mu.Unlock()
		if _, ok := blobs[d]; !ok {
			return nil, status.Error(codes.NotFound, "no content")
		}
		return one(&contentapi.InfoResponse{Info: info(d)})
	})
	f.on("/containerd.services.content.v1.Content/Read", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		rq := q.(*contentapi.ReadContentRequest)
		mu.Lock()
		defer mu.Unlock()
		b, ok := blobs[digest.Digest(rq.GetDigest())]
		if !ok {
			return nil, status.Error(codes.NotFound, "no content")
		}
		end := int64(len(b))
		if rq.GetSize() > 0 && rq.GetOffset()+rq.GetSize() < end {
			end = rq.GetOffset() + rq.GetSize()
		}
		return one(&contentapi.ReadContentResponse{Offset: rq.GetOffset(), Data: b[rq.GetOffset():end]})
	})
	f.on("/containerd.services.content.v1.Content/Update", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		u := q.(*contentapi.UpdateRequest)
		d := digest.Digest(u.GetInfo().GetDigest())
		mu.Lock()
		defer mu.Unlock()
		if labels[d] == nil {
			labels[d] = map[string]string{}
		}
		for k, v := range u.GetInfo().GetLabels() {
			labels[d][k] = v
		}
		return one(&contentapi.UpdateResponse{Info: info(d)})
	})
	f.on("/containerd.services.images.v1.Images/Create", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		return one(&imagesapi.CreateImageResponse{Image: q.(*imagesapi.CreateImageRequest).GetImage()})
	})
	return blobs
}

// testOCIImage is a config, one layer and a manifest naming them.
func testOCIImage() (blobs [][]byte, manifest ocispec.Descriptor) {
	layer := []byte("a gzip layer stands here")
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:` + digest.FromString("x").Encoded() + `"]}}`)
	m, _ := json.Marshal(ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: digest.FromBytes(config), Size: int64(len(config))},
		Layers:    []ocispec.Descriptor{{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromBytes(layer), Size: int64(len(layer))}},
	})
	return [][]byte{config, layer, m}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(m), Size: int64(len(m))}
}

// TestBuildImportFlowsThroughTheGate: the import's content writes, label
// updates and image record, made by containerd's client library as the
// agent makes them, all pass the gate unrefused.
func TestBuildImportFlowsThroughTheGate(t *testing.T) {
	r := newRig(t, testPolicy())
	stored := contentContainerd(r)
	client, ctx := agentClient(t, r)

	lease, err := client.LeasesService().Create(ctx, leases.WithRandomID(), leases.WithExpiration(time.Hour))
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	ctx = leases.WithLease(ctx, lease.ID)
	cs := client.ContentStore()
	blobs, manifest := testOCIImage()
	for _, b := range blobs {
		desc := ocispec.Descriptor{Digest: digest.FromBytes(b), Size: int64(len(b))}
		if err := content.WriteBlob(ctx, cs, "aerolvm-build-"+desc.Digest.Encoded(), bytes.NewReader(b), desc); err != nil {
			t.Fatalf("WriteBlob %s: %v", desc.Digest, err)
		}
	}
	// Content the store already has: the writer stops at STAT.
	if err := content.WriteBlob(ctx, cs, "again", bytes.NewReader(blobs[1]), ocispec.Descriptor{Digest: digest.FromBytes(blobs[1]), Size: int64(len(blobs[1]))}); err != nil {
		t.Fatalf("WriteBlob of present content: %v", err)
	}
	if err := images.Walk(ctx, images.SetChildrenLabels(cs, images.ChildrenHandler(cs)), manifest); err != nil {
		t.Fatalf("label walk: %v", err)
	}
	info, err := cs.Info(ctx, manifest.Digest)
	if err != nil || info.Labels["containerd.io/gc.ref.content.l.0"] != digest.FromBytes(blobs[1]).String() {
		t.Fatalf("manifest labels %v, %v", info.Labels, err)
	}
	if _, err := client.ImageService().Create(ctx, images.Image{Name: "aerolvm-build/0123456789abcdef:latest", Target: manifest}); err != nil {
		t.Fatalf("image Create: %v", err)
	}
	if err := client.LeasesService().Delete(ctx, lease); err != nil {
		t.Fatalf("lease Delete: %v", err)
	}
	if refs := r.refused(); len(refs) != 0 {
		t.Fatalf("the gate refused the import's own calls: %+v", refs)
	}
	if len(stored) != len(blobs) {
		t.Fatalf("containerd holds %d blobs, want %d", len(stored), len(blobs))
	}
	for _, want := range []string{
		"/containerd.services.content.v1.Content/Write",
		"/containerd.services.content.v1.Content/Read",
		"/containerd.services.content.v1.Content/Update",
		"/containerd.services.images.v1.Images/Create",
	} {
		if !slices.Contains(r.fake.methodsSeen(), want) {
			t.Errorf("the import never reached %s", want)
		}
	}
}

// TestBuildImportBrokenAgent: an agent that tries to land a build anywhere
// but its own namespace, or to hand containerd the archive itself, is
// refused before containerd hears of it.
func TestBuildImportBrokenAgent(t *testing.T) {
	r := newRig(t, testPolicy())
	contentContainerd(r)
	_, manifest := testOCIImage()
	img := &imagesapi.Image{Name: "aerolvm-build/x:latest", Target: &types.Descriptor{MediaType: manifest.MediaType, Digest: manifest.Digest.String(), Size: manifest.Size}}
	t.Run("an image record in another namespace", func(t *testing.T) {
		_, err := r.invoke(otherNSCtx(), "/containerd.services.images.v1.Images/Create", &imagesapi.CreateImageRequest{Image: img})
		r.wantRefused(err, "/containerd.services.images.v1.Images/Create", ReasonNamespace)
	})
	t.Run("a content write in another namespace", func(t *testing.T) {
		_, err := r.invoke(otherNSCtx(), "/containerd.services.content.v1.Content/Write", &contentapi.WriteContentRequest{Action: contentapi.WriteAction_STAT, Ref: "x"})
		r.wantRefused(err, "/containerd.services.content.v1.Content/Write", ReasonNamespace)
	})
	t.Run("labels in another namespace", func(t *testing.T) {
		_, err := r.invoke(otherNSCtx(), "/containerd.services.content.v1.Content/Update", &contentapi.UpdateRequest{
			Info: &contentapi.Info{Digest: manifest.Digest.String()}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}})
		r.wantRefused(err, "/containerd.services.content.v1.Content/Update", ReasonNamespace)
	})
	// The transfer service would unpack an archive containerd reads as
	// root; its stream service carries the archive's bytes. Neither is an
	// import path the agent has.
	for _, name := range []string{"/containerd.services.transfer.v1.Transfer/Transfer", "/containerd.services.streaming.v1.Streaming/Stream"} {
		t.Run(name, func(t *testing.T) {
			_, err := r.invoke(nsCtx(), name, &imagesapi.CreateImageRequest{Image: img})
			r.wantRefused(err, name, ReasonMethod)
		})
	}
}

// otherNSCtx is a call in a namespace that is not the agent's.
func otherNSCtx() context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), namespaces.GRPCHeader, "k8s.io")
}
