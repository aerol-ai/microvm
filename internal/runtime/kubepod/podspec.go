package kubepod

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Labels and annotations on every sandbox pod. The worker label is how a
// worker finds its own pods (ListManaged) and how it tells its pod from
// another worker's pod of the same name after a failover.
const (
	LabelName      = "app.kubernetes.io/name"
	LabelComponent = "app.kubernetes.io/component"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelWorker    = "aerolvm.io/node"
	// AnnotationSandboxID is the sandbox's own ID. The pod name is the ID
	// too, except for an ID that is not a DNS label (podName).
	AnnotationSandboxID = "aerolvm.io/sandbox-id"
	// AnnotationRuntime is the AerolVM runtime name the create asked for;
	// spec.runtimeClassName holds the RuntimeClass it maps to.
	AnnotationRuntime = "aerolvm.io/runtime"

	componentSandbox = "sandbox"
	managedByWorker  = "aerolvm-worker"
)

// Where toolboxd sits in a sandbox pod. The init container copies it into
// an emptyDir; the sandbox container mounts that read-only and runs it as
// PID 1, so it can end the sandbox's processes (the lease fence, plan D17).
const (
	toolboxVolume    = "aerolvm-toolbox"
	toolboxMountDir  = "/aerolvm/toolbox"
	toolboxBinary    = toolboxMountDir + "/toolboxd"
	initContainer    = "toolbox-install"
	sandboxContainer = "sandbox"
	// toolboxVolumeLimit holds one toolboxd binary with room to spare.
	toolboxVolumeLimit = "256Mi"
)

// initResources is the init container's requests and limits. They are
// equal (with the sandbox container's) so the pod is Guaranteed: the
// kubelet evicts it last under memory pressure. Copying one file needs
// little, and a pod's effective request is the larger of its init and
// regular containers', so this never adds to the sandbox's size.
var initResources = map[string]string{"cpu": "100m", "memory": "64Mi"}

// nobodyUID runs the init container: it only copies a file into the
// emptyDir, which needs no root.
const nobodyUID int64 = 65532

// droppedCapabilities are dropped from the sandbox container. The
// container runtime's default set is the sandbox set
// (rootpolicy.SandboxCapabilities) plus these, so a sandbox pod gets the
// same capabilities as a sandbox on the default install.
func droppedCapabilities() []string {
	out := make([]string, 0, len(rootpolicy.DroppedCapabilities()))
	for _, c := range rootpolicy.DroppedCapabilities() {
		out = append(out, strings.TrimPrefix(c, "CAP_"))
	}
	return out
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// hashedNamePrefix starts the name of a pod whose sandbox ID is not a DNS
// label. Generated IDs ("sb-" and 16 hex digits) never take this form.
const hashedNamePrefix = "sb-h-"

// podName is the pod's name for a sandbox ID or container ref. A pod name
// is a DNS label here (63 characters, lowercase letters, digits and
// hyphens), so a pod's hostname is its name. The service's generated IDs
// already are one and are used as they are, which is what makes a retried
// create find its pod. Any other ID gets a fixed name from its hash.
func podName(id string) string {
	if len(id) <= 63 && dnsLabel.MatchString(id) {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return hashedNamePrefix + hex.EncodeToString(sum[:16])
}

// Refusals: what a pod-mode create cannot do (yet). Each is an error, never
// a silent drop, because dropping env or a mount would hand the caller a
// sandbox other than the one asked for (plan R18).
var (
	ErrEnvNotSupported = errors.New("kubepod: env is handed to the sandbox over the worker's mTLS link, which is not built yet; " +
		"a pod spec is stored in etcd, so env never goes in one")
	ErrHostMountsNotSupported   = errors.New("kubepod: a sandbox pod has no host paths, so host mounts are refused")
	ErrGPUsNotSupported         = errors.New("kubepod: GPUs are not offered in pod mode")
	ErrRegistryAuthNotSupported = errors.New("kubepod: per-create registry credentials are not taken in pod mode: they would need a Kubernetes Secret per sandbox")
	ErrRuntimeNotOffered        = errors.New("kubepod: this runtime has no RuntimeClass in this install")
)

// renderPod builds the pod for a create. Nothing secret goes in it: the
// object is stored in etcd and anyone who may read pods in the namespace
// sees it (plan D8). So the toolbox token and env are not here; the worker
// hands them to toolboxd over mTLS after the pod starts.
func (d *Driver) renderPod(req models.CreateSandboxRequest, sandboxID string) (*Pod, error) {
	if len(req.Env) > 0 {
		return nil, ErrEnvNotSupported
	}
	if req.GPUs != nil {
		return nil, ErrGPUsNotSupported
	}
	if req.Registry != nil {
		return nil, ErrRegistryAuthNotSupported
	}
	image := strings.TrimSpace(req.Image)
	if image == "" {
		return nil, errors.New("kubepod: image is required")
	}
	runtimeName := strings.TrimSpace(req.Runtime)
	if runtimeName == "" {
		runtimeName = d.cfg.DefaultRuntime
	}
	class, ok := d.cfg.RuntimeClasses[runtimeName]
	if !ok {
		return nil, fmt.Errorf("%w: %q (offered: %s)", ErrRuntimeNotOffered, runtimeName, strings.Join(d.offeredRuntimes(), ", "))
	}

	limits := map[string]string{
		"cpu":    cpuQuantity(req.CPU),
		"memory": memoryQuantity(req.MemoryMB),
	}
	if req.DiskGB > 0 {
		// The kubelet evicts a pod past its ephemeral-storage limit: the
		// disk size a create asks for is enforced, writable layer and
		// emptyDirs together.
		limits["ephemeral-storage"] = strconv.Itoa(req.DiskGB) + "Gi"
	}
	env := []EnvVar{{Name: "SB_SANDBOX_ID", Value: sandboxID}}
	if d.cfg.ToolboxPort != defaultToolboxPort {
		env = append(env, EnvVar{Name: "SB_TOOLBOX_PORT", Value: strconv.Itoa(d.cfg.ToolboxPort)})
	}

	name := podName(sandboxID)
	return &Pod{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: ObjectMeta{
			Name:      name,
			Namespace: d.cfg.Namespace,
			Labels: map[string]string{
				LabelName:      "aerolvm",
				LabelComponent: componentSandbox,
				LabelManagedBy: managedByWorker,
				LabelWorker:    d.cfg.WorkerID,
			},
			Annotations: map[string]string{
				AnnotationSandboxID: sandboxID,
				AnnotationRuntime:   runtimeName,
			},
		},
		Spec: PodSpec{
			RuntimeClassName: class,
			// toolboxd is PID 1. When it exits the sandbox has ended, and
			// the kubelet must not start a second copy behind the
			// worker's back (plan D17).
			RestartPolicy:                 "Never",
			AutomountServiceAccountToken:  boolPtr(false),
			EnableServiceLinks:            boolPtr(false),
			TerminationGracePeriodSeconds: int64Ptr(int64(d.cfg.StopGrace.Seconds())),
			SecurityContext: &PodSecurityContext{
				SeccompProfile: &SeccompProfile{Type: "RuntimeDefault"},
			},
			InitContainers: []Container{{
				Name:      initContainer,
				Image:     d.cfg.ToolboxImage,
				Command:   d.installCommand(),
				Resources: &Resources{Requests: initResources, Limits: initResources},
				VolumeMounts: []VolumeMount{{
					Name: toolboxVolume, MountPath: toolboxMountDir,
				}},
				SecurityContext: &SecurityContext{
					Privileged:               boolPtr(false),
					AllowPrivilegeEscalation: boolPtr(false),
					Capabilities:             &Capabilities{Drop: []string{"ALL"}},
					RunAsNonRoot:             boolPtr(true),
					RunAsUser:                int64Ptr(nobodyUID),
					RunAsGroup:               int64Ptr(nobodyUID),
					ReadOnlyRootFilesystem:   boolPtr(true),
				},
			}},
			Containers: []Container{{
				Name:    sandboxContainer,
				Image:   image,
				Command: []string{toolboxBinary},
				Args:    append([]string(nil), req.ContainerCommand...),
				Env:     env,
				// Requests equal limits: the sandbox gets what it asked for
				// and no more, and the pod is Guaranteed.
				Resources: &Resources{Requests: limits, Limits: limits},
				VolumeMounts: []VolumeMount{{
					Name: toolboxVolume, MountPath: toolboxMountDir, ReadOnly: true,
				}},
				SecurityContext: &SecurityContext{
					Privileged: boolPtr(false),
					// The default install sets no_new_privs on every
					// sandbox too.
					AllowPrivilegeEscalation: boolPtr(false),
					Capabilities:             &Capabilities{Drop: droppedCapabilities()},
				},
			}},
			Volumes: []Volume{{
				Name:     toolboxVolume,
				EmptyDir: &EmptyDir{SizeLimit: toolboxVolumeLimit},
			}},
		},
	}, nil
}

// installCommand is the init container's command: toolboxd copies itself
// into the toolbox volume (cmd/toolboxd install_self.go).
func (d *Driver) installCommand() []string {
	return []string{d.cfg.ToolboxPath, "--install-to", toolboxBinary}
}

// cpuQuantity is cores as millicores ("1500m"). Zero is the service's
// default size, which it normally fills in before the driver is called.
func cpuQuantity(cores float64) string {
	if cores <= 0 {
		cores = models.DefaultCPU
	}
	m := int64(math.Ceil(cores * 1000))
	if m < 1 {
		m = 1
	}
	return strconv.FormatInt(m, 10) + "m"
}

// memoryQuantity is MiB as a quantity ("512Mi").
func memoryQuantity(mb int) string {
	if mb <= 0 {
		mb = models.DefaultMemoryMB
	}
	return strconv.Itoa(mb) + "Mi"
}
