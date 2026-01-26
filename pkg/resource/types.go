package resource

import "time"

const (
	// MacOSRuntime is the runtime name for macOS virtual machines.
	MacOSRuntime = "vz"

	// ContainerRuntime is the runtime name for containerized workloads.
	ContainerRuntime = "docker"

	// HostProcessRuntime is the runtime name for native host processes.
	HostProcessRuntime = "hostprocess"

	// RuntimeAnnotationKey is the annotation key for specifying container runtime.
	// Values: "vz" (default for first container), "docker" (default for other containers), "hostprocess"
	RuntimeAnnotationKey = "vz.kubernetes.io/runtime"

	// RuntimeAnnotationPrefix is the prefix for container-specific runtime annotations.
	// Format: vz.kubernetes.io/runtime.<container-name>=<runtime>
	RuntimeAnnotationPrefix = RuntimeAnnotationKey + "."
)

type ExecAction struct {
	// Command is the command line to execute inside the container.
	// Exit status of 0 is treated as live/healthy and non-zero is unhealthy.
	Command []string

	// TimeoutDuration is the maximum duration to wait for the command to complete.
	TimeoutDuration time.Duration
}
