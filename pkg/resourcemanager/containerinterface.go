package resourcemanager

import (
	"context"
	"io"

	"github.com/agoda-com/macOS-vz-kubelet/internal/volumes"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	stats "k8s.io/kubelet/pkg/apis/stats/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// HostProcessParams contains the parameters needed to create a host process.
type HostProcessParams struct {
	PodNamespace string
	PodName      string
	Name         string
	Command      []string
	Args         []string
	Env          []corev1.EnvVar
	WorkingDir   string
	Mounts       []volumes.Mount
}

// ContainerParams is a struct that contains the parameters needed to create a container.
type ContainerParams struct {
	PodNamespace, PodName string

	Name            string
	Image           string
	ImagePullPolicy corev1.PullPolicy
	RegistryCreds   resource.RegistryCredentials

	Mounts          []volumes.Mount
	Env             []corev1.EnvVar
	Command         []string
	Args            []string
	WorkingDir      string
	TTY             bool
	Stdin           bool
	StdinOnce       bool
	PostStartAction *resource.ExecAction
}

// ContainersClient is an interface that defines the methods that a ContainersClient implementation should provide.
// In the future, we may evaluate using containerd through colima or similar instead of the heavy docker client library.
type ContainersClient interface {
	CreateContainer(ctx context.Context, params ContainerParams) error
	RemoveContainers(ctx context.Context, podNs, podName string, gracePeriod int64) error
	GetContainers(ctx context.Context, podNs, podName string) ([]resource.Container, error)
	GetContainersListResult(ctx context.Context) (map[types.NamespacedName][]resource.Container, error)
	GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts api.ContainerLogOpts) (io.ReadCloser, error)
	ExecInContainer(ctx context.Context, namespace, name, containerName string, cmd []string, attach api.AttachIO) error
	AttachToContainer(ctx context.Context, namespace, name, containerName string, attach api.AttachIO) error
	IsContainerPresent(ctx context.Context, podNs, podName, containerName string) bool
	GetContainerStats(ctx context.Context, podNs, podName string, containerName string) (stats.ContainerStats, error)
}

// HostProcessClient is an interface for managing native host processes as pods.
// This enables running macOS binaries directly on the host (e.g., CNI agents, DaemonSets).
type HostProcessClient interface {
	CreateProcess(ctx context.Context, params HostProcessParams) error
	RemoveProcesses(ctx context.Context, podNs, podName string, gracePeriod int64) error
	GetProcesses(ctx context.Context, podNs, podName string) ([]resource.Process, error)
	GetProcessesListResult(ctx context.Context) (map[types.NamespacedName][]resource.Process, error)
	GetProcessLogs(ctx context.Context, namespace, podName, processName string, opts api.ContainerLogOpts) (io.ReadCloser, error)
	ExecInProcess(ctx context.Context, namespace, podName, processName string, cmd []string, attach api.AttachIO) error
	IsProcessPresent(ctx context.Context, podNs, podName, processName string) bool
	GetProcessStats(ctx context.Context, podNs, podName, processName string) (stats.ContainerStats, error)
}
