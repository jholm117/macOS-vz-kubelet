package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/internal/utils"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/client"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// virtualizationGroupToPod converts a VirtualizationGroup to a Kubernetes Pod status.
func (p *MacOSVZProvider) virtualizationGroupToPod(ctx context.Context, vg *client.VirtualizationGroup, namespace, name string) (*corev1.Pod, error) {
	pod, err := p.podLister.Pods(namespace).Get(name)
	if err != nil {
		return nil, err
	}

	podState := p.buildPodStatus(ctx, vg, pod)
	updatedPod := pod.DeepCopy()
	updatedPod.Status = *podState

	return updatedPod, nil
}

// buildPodStatus constructs the pod's status from the provided virtualization group.
func (p *MacOSVZProvider) buildPodStatus(_ context.Context, vg *client.VirtualizationGroup, pod *corev1.Pod) *corev1.PodStatus {
	var firstContainerStartTime, lastUpdateTime time.Time

	macOSVM := vg.MacOSVirtualMachine
	groupContainers := vg.Containers
	groupProcesses := vg.Processes

	// Use VPC IP if available, otherwise fall back to internal VM IP
	podIp := vg.VPCIPAddress
	if podIp == "" {
		podIp = macOSVM.IPAddress()
	}
	containerStatuses := make([]corev1.ContainerStatus, 0, len(pod.Spec.Containers))

	// Get runtime for each container from annotations
	containerRuntimes := getContainerRuntimes(pod)

	for i, c := range pod.Spec.Containers {
		// vz: always assume that first container is macOS container
		if i == 0 {
			state := macOSVM.State()
			started := podIp != "" // TODO: this needs to indicate whether postStart hook has finished
			ready := state == resource.VirtualMachineStateRunning

			if startedAt := macOSVM.StartedAt(); startedAt != nil {
				firstContainerStartTime = *startedAt
				lastUpdateTime = firstContainerStartTime
			}
			if finishedAt := macOSVM.FinishedAt(); finishedAt != nil {
				lastUpdateTime = *finishedAt
			}

			containerStatus := corev1.ContainerStatus{
				Name:         c.Name,
				State:        vmToContainerState(macOSVM, pod.CreationTimestamp.Time),
				Ready:        ready,
				Started:      &started,
				RestartCount: 0,
				Image:        c.Image,
				ImageID:      "",
				ContainerID:  utils.GetContainerID(resource.MacOSRuntime, c.Name),
			}

			// Add the container status to the list.
			containerStatuses = append(containerStatuses, containerStatus)
			continue
		}

		// Check if this container is a host process
		runtime := containerRuntimes[c.Name]
		if runtime == resource.HostProcessRuntime {
			process, err := getProcessWithName(c.Name, groupProcesses)
			if err != nil {
				continue
			}

			state := process.State.Status
			started := state == resource.ProcessStatusRunning
			ready := state == resource.ProcessStatusRunning

			containerStatus := corev1.ContainerStatus{
				Name:         c.Name,
				State:        processToContainerState(process, pod.CreationTimestamp.Time),
				Ready:        ready,
				Started:      &started,
				RestartCount: 0,
				Image:        c.Image,
				ImageID:      "",
				ContainerID:  utils.GetContainerID(resource.HostProcessRuntime, c.Name),
			}

			startedAt := process.State.StartedAt
			finishedAt := process.State.FinishedAt
			if !startedAt.IsZero() &&
				(startedAt.Before(firstContainerStartTime) || firstContainerStartTime.IsZero()) {
				firstContainerStartTime = startedAt
			}
			if startedAt.After(lastUpdateTime) {
				lastUpdateTime = startedAt
			}
			if !finishedAt.IsZero() &&
				(finishedAt.After(lastUpdateTime) || lastUpdateTime.IsZero()) {
				lastUpdateTime = finishedAt
			}

			containerStatuses = append(containerStatuses, containerStatus)
			continue
		}

		// Default: Docker container
		container, err := getContainerWithName(c.Name, groupContainers)
		if err != nil {
			continue
		}

		state := container.State.Status
		started := state == resource.ContainerStatusRunning
		ready := state == resource.ContainerStatusRunning

		containerStatus := corev1.ContainerStatus{
			Name:         c.Name,
			State:        containerToContainerState(container, pod.CreationTimestamp.Time),
			Ready:        ready,
			Started:      &started,
			RestartCount: 0,
			Image:        c.Image,
			ImageID:      "",
			ContainerID:  utils.GetContainerID(resource.ContainerRuntime, c.Name),
		}

		startedAt := container.State.StartedAt
		finishedAt := container.State.FinishedAt
		if !startedAt.IsZero() &&
			(startedAt.Before(firstContainerStartTime) || firstContainerStartTime.IsZero()) {
			firstContainerStartTime = startedAt
		}
		if startedAt.After(lastUpdateTime) {
			lastUpdateTime = startedAt
		}
		if !finishedAt.IsZero() &&
			(finishedAt.After(lastUpdateTime) || lastUpdateTime.IsZero()) {
			lastUpdateTime = finishedAt
		}

		// Add the container status to the list.
		containerStatuses = append(containerStatuses, containerStatus)
	}

	var startTime *metav1.Time
	if !firstContainerStartTime.IsZero() {
		startTime = &metav1.Time{Time: firstContainerStartTime}
	}
	return &corev1.PodStatus{
		Phase:             getPodPhaseFromVirtualizationGroup(vg),
		Conditions:        getPodConditionsFromVirtualizationGroup(vg, pod.CreationTimestamp.Time, firstContainerStartTime, lastUpdateTime),
		Message:           "",
		Reason:            "",
		HostIP:            p.nodeIPAddress,
		PodIP:             podIp,
		StartTime:         startTime,
		ContainerStatuses: containerStatuses,
	}
}

// vmToContainerState converts the macOS VM state to a Kubernetes container state.
func vmToContainerState(vm resource.VirtualMachine, podCreationTime time.Time) corev1.ContainerState {
	startTime := podCreationTime
	finishTime := podCreationTime
	if startedAt := vm.StartedAt(); startedAt != nil {
		startTime = *startedAt
	}
	if finishedAt := vm.FinishedAt(); finishedAt != nil {
		finishTime = *finishedAt
	}

	switch vm.State() {
	case resource.VirtualMachineStatePreparing:
		return corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{
				Reason:  "Downloading",
				Message: "VM is downloading image from the registry",
			},
		}
	case resource.VirtualMachineStateStarting:
		return corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{
				Reason:  "Starting",
				Message: "VM is starting",
			},
		}
	case resource.VirtualMachineStateRunning:
		return corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{
				StartedAt: metav1.NewTime(startTime),
			},
		}
	case resource.VirtualMachineStateTerminating, resource.VirtualMachineStateTerminated:
		return corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				ExitCode:   0,
				Reason:     "Completed",
				Message:    "VM is stopped",
				StartedAt:  metav1.NewTime(startTime),
				FinishedAt: metav1.NewTime(finishTime),
			},
		}
	case resource.VirtualMachineStateFailed:
		return corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				ExitCode:   1,
				Reason:     "Error",
				Message:    fmt.Sprintf("VM has failed: %v", vm.Error()),
				StartedAt:  metav1.NewTime(startTime),
				FinishedAt: metav1.NewTime(finishTime),
			},
		}
	}

	return corev1.ContainerState{}
}

// containerToContainerState converts the container state to a Kubernetes container state.
func containerToContainerState(container resource.Container, podCreationTime time.Time) corev1.ContainerState {
	startTime := podCreationTime
	finishTime := podCreationTime
	if !container.State.StartedAt.IsZero() {
		startTime = container.State.StartedAt
	}
	if !container.State.FinishedAt.IsZero() {
		finishTime = container.State.FinishedAt
	}

	switch container.State.Status {
	case resource.ContainerStatusWaiting:
		if container.State.Error != "" {
			// mimic standard kubernetes behavior for
			// container error during pre-running stage
			return corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason:  "Error",
					Message: container.State.Error,
				},
			}
		}
		return corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{
				Reason: "ContainerCreating",
			},
		}
	case resource.ContainerStatusCreated:
		return corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{
				Reason:  "ContainerCreated",
				Message: "Container has been created",
			},
		}
	case resource.ContainerStatusRunning:
		return corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{
				StartedAt: metav1.NewTime(startTime),
			},
		}
	case resource.ContainerStatusPaused:
		return corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{
				Reason:  "ContainerPaused",
				Message: "Container is paused",
			},
		}
	case resource.ContainerStatusRestarting:
		return corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{
				Reason:  "ContainerRestarting",
				Message: "Container is restarting",
			},
		}
	case resource.ContainerStatusOOMKilled:
		return corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				ExitCode:   137,
				Reason:     "OOMKilled",
				Message:    "Container was killed due to out of memory",
				StartedAt:  metav1.NewTime(startTime),
				FinishedAt: metav1.NewTime(finishTime),
			},
		}
	case resource.ContainerStatusDead:
		return corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				ExitCode:   int32(container.State.ExitCode),
				Reason:     "ContainerDead",
				Message:    container.State.Error,
				StartedAt:  metav1.NewTime(startTime),
				FinishedAt: metav1.NewTime(finishTime),
			},
		}
	default:
		return corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				ExitCode:   int32(container.State.ExitCode),
				Reason:     "Unknown",
				Message:    container.State.Error,
				StartedAt:  metav1.NewTime(startTime),
				FinishedAt: metav1.NewTime(finishTime),
			},
		}
	}
}

// getContainerWithName finds and returns a container with the specified name from a list of containers.
func getContainerWithName(name string, list []resource.Container) (resource.Container, error) {
	for _, c := range list {
		if c.Name == name {
			return c, nil
		}
	}

	return resource.Container{}, fmt.Errorf("container %s not found", name)
}

// getProcessWithName finds and returns a process with the specified name from a list of processes.
func getProcessWithName(name string, list []resource.Process) (resource.Process, error) {
	for _, p := range list {
		if p.Name == name {
			return p, nil
		}
	}

	return resource.Process{}, fmt.Errorf("process %s not found", name)
}

// getContainerRuntimes returns a map of container names to their runtime types based on pod annotations.
func getContainerRuntimes(pod *corev1.Pod) map[string]string {
	runtimes := make(map[string]string)
	for i, c := range pod.Spec.Containers {
		// First container is always macOS VM
		if i == 0 {
			runtimes[c.Name] = resource.MacOSRuntime
			continue
		}

		// Check for container-specific annotation
		annotationKey := resource.RuntimeAnnotationPrefix + c.Name
		if runtime, ok := pod.Annotations[annotationKey]; ok {
			runtimes[c.Name] = runtime
		} else {
			runtimes[c.Name] = resource.ContainerRuntime
		}
	}
	return runtimes
}

// processToContainerState converts a host process state to a Kubernetes container state.
func processToContainerState(process resource.Process, podCreationTime time.Time) corev1.ContainerState {
	startTime := podCreationTime
	finishTime := podCreationTime
	if !process.State.StartedAt.IsZero() {
		startTime = process.State.StartedAt
	}
	if !process.State.FinishedAt.IsZero() {
		finishTime = process.State.FinishedAt
	}

	switch process.State.Status {
	case resource.ProcessStatusPending:
		return corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{
				Reason:  "ProcessPending",
				Message: "Host process is pending",
			},
		}
	case resource.ProcessStatusRunning:
		return corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{
				StartedAt: metav1.NewTime(startTime),
			},
		}
	case resource.ProcessStatusSucceeded:
		return corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				ExitCode:   int32(process.State.ExitCode),
				Reason:     "Completed",
				Message:    "Host process completed successfully",
				StartedAt:  metav1.NewTime(startTime),
				FinishedAt: metav1.NewTime(finishTime),
			},
		}
	case resource.ProcessStatusFailed:
		return corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				ExitCode:   int32(process.State.ExitCode),
				Reason:     "Error",
				Message:    process.State.Error,
				StartedAt:  metav1.NewTime(startTime),
				FinishedAt: metav1.NewTime(finishTime),
			},
		}
	}

	return corev1.ContainerState{}
}

// getPodPhaseFromVirtualizationGroup determines the pod phase based on the state of the virtualization group.
func getPodPhaseFromVirtualizationGroup(vg *client.VirtualizationGroup) corev1.PodPhase {
	// Get the macOS VM, containers, and processes
	macOSVM := vg.MacOSVirtualMachine
	groupContainers := vg.Containers
	groupProcesses := vg.Processes
	hasIP := macOSVM.IPAddress() != ""

	// Determine the pod phase based on the macOS VM state
	switch macOSVM.State() {
	case resource.VirtualMachineStatePreparing, resource.VirtualMachineStateStarting:
		return corev1.PodPending
	case resource.VirtualMachineStateTerminated:
		return corev1.PodSucceeded
	case resource.VirtualMachineStateFailed:
		return corev1.PodFailed
	case resource.VirtualMachineStateTerminating, resource.VirtualMachineStateRunning:
		// If there are no group containers or processes, consider VM as a single source of truth
		if len(groupContainers) == 0 && len(groupProcesses) == 0 {
			if !hasIP {
				return corev1.PodPending
			}
			return corev1.PodRunning
		}
	}

	// Determine the pod phase based on the container statuses
	allRunning := true
	for _, container := range groupContainers {
		switch container.State.Status {
		case resource.ContainerStatusWaiting, resource.ContainerStatusCreated:
			return corev1.PodPending
		case resource.ContainerStatusRunning:
			// Continue checking other containers
		case resource.ContainerStatusOOMKilled, resource.ContainerStatusUnknown:
			return corev1.PodFailed
		default:
			allRunning = false
		}
	}

	// Determine the pod phase based on the process statuses
	for _, process := range groupProcesses {
		switch process.State.Status {
		case resource.ProcessStatusPending:
			return corev1.PodPending
		case resource.ProcessStatusRunning:
			// Continue checking other processes
		case resource.ProcessStatusFailed:
			return corev1.PodFailed
		case resource.ProcessStatusSucceeded:
			allRunning = false
		}
	}

	if !hasIP {
		return corev1.PodPending
	}

	if allRunning {
		return corev1.PodRunning
	}

	return corev1.PodUnknown
}

// getPodConditionsFromVirtualizationGroup determines the pod conditions based on the state of the virtualization group.
func getPodConditionsFromVirtualizationGroup(vg *client.VirtualizationGroup, podCreationTime, firstContainerStartTime, lastUpdateTime time.Time) []corev1.PodCondition {
	// Get the macOS VM, containers, and processes
	macOSVM := vg.MacOSVirtualMachine
	groupContainers := vg.Containers
	groupProcesses := vg.Processes

	// Initialize pod conditions
	conditions := []corev1.PodCondition{}

	// Determine PodScheduled condition
	podScheduledCondition := corev1.PodCondition{
		Type:               corev1.PodScheduled,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: podCreationTime},
	}
	conditions = append(conditions, podScheduledCondition)

	// Determine Initialized condition
	initializedCondition := corev1.PodCondition{
		Type:               corev1.PodInitialized,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Time{Time: firstContainerStartTime},
	}

	// Determine Ready condition
	readyCondition := corev1.PodCondition{
		Type:               corev1.PodReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Time{Time: lastUpdateTime},
	}

	// Check macOS VM state
	switch macOSVM.State() {
	case resource.VirtualMachineStatePreparing, resource.VirtualMachineStateStarting:
		// Pod is not yet initialized or ready
		initializedCondition.Status = corev1.ConditionFalse
		readyCondition.Status = corev1.ConditionFalse
	case resource.VirtualMachineStateTerminated:
		// Pod is initialized but not ready
		initializedCondition.Status = corev1.ConditionTrue
		readyCondition.Status = corev1.ConditionFalse
	case resource.VirtualMachineStateFailed:
		// Pod is not initialized and not ready
		initializedCondition.Status = corev1.ConditionFalse
		readyCondition.Status = corev1.ConditionFalse
	case resource.VirtualMachineStateTerminating, resource.VirtualMachineStateRunning:
		// Check container states
		allRunning := true
		for _, container := range groupContainers {
			switch container.State.Status {
			case resource.ContainerStatusWaiting, resource.ContainerStatusCreated:
				// Pod is not yet initialized or ready
				initializedCondition.Status = corev1.ConditionFalse
				readyCondition.Status = corev1.ConditionFalse
			case resource.ContainerStatusRunning:
				// Continue checking other containers
			case resource.ContainerStatusOOMKilled, resource.ContainerStatusUnknown:
				// Pod is not initialized and not ready
				initializedCondition.Status = corev1.ConditionFalse
				readyCondition.Status = corev1.ConditionFalse
				allRunning = false
			default:
				allRunning = false
			}
		}

		// Check process states
		for _, process := range groupProcesses {
			switch process.State.Status {
			case resource.ProcessStatusPending:
				// Pod is not yet initialized or ready
				initializedCondition.Status = corev1.ConditionFalse
				readyCondition.Status = corev1.ConditionFalse
			case resource.ProcessStatusRunning:
				// Continue checking other processes
			case resource.ProcessStatusFailed:
				// Pod is not initialized and not ready
				initializedCondition.Status = corev1.ConditionFalse
				readyCondition.Status = corev1.ConditionFalse
				allRunning = false
			case resource.ProcessStatusSucceeded:
				allRunning = false
			}
		}

		if allRunning {
			// Pod is initialized and ready
			initializedCondition.Status = corev1.ConditionTrue
			readyCondition.Status = corev1.ConditionTrue
		}
	}

	// Append conditions to the list
	conditions = append(conditions, initializedCondition, readyCondition)

	return conditions
}
