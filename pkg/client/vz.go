package client

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/agoda-com/macOS-vz-kubelet/internal/utils"
	"github.com/agoda-com/macOS-vz-kubelet/internal/volumes"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/cni"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/event"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"
	rm "github.com/agoda-com/macOS-vz-kubelet/pkg/resourcemanager"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/vm"

	"github.com/virtual-kubelet/virtual-kubelet/errdefs"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	"github.com/virtual-kubelet/virtual-kubelet/trace"
	stats "k8s.io/kubelet/pkg/apis/stats/v1alpha1"

	docker "github.com/moby/moby/client"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// PodMountsDir is the directory where pod volumes are mounted.
	// It is createdinside the cache directory.
	PodMountsDir = "mounts"

	// Timeout for executing post-start command.
	//
	// @note: While pre-stop hook timeout is suppored by simply setting terminationGracePeriodSeconds,
	// as of now k8s does not support setting custom timeout for post-start command at all.
	// Setting this constant as default for now (usually post-start should be something lite anyway).
	PostStartCommandTimeout = 10 * time.Second
)

var (
	// errVirtualizationGroupNotFound is returned when a virtualization group is not found.
	errVirtualizationGroupNotFound = errdefs.NotFound("virtualization group not found")
)

// virtualizationGroupExtras contains additional information for a virtualization group.
type virtualizationGroupExtras struct {
	rootDir    string             // root directory for the volumes of the pod
	cancelFunc context.CancelFunc // context cancellation function for the virtualization group

	deleteOnce sync.Once  // ensures that the virtualization group is deleted only once
	deleteDone chan error // signals that the virtualization group has been deleted
}

// VzClientAPIs is a concrete implementation of VzClientInterface, using MacOSClient and ContainerClient.
type VzClientAPIs struct {
	MacOSClient        *rm.MacOSClient
	ContainerClient    rm.ContainersClient    // Optional
	HostProcessClient  rm.HostProcessClient   // Optional
	CNIClient          *cni.Client            // Optional - for VPC networking

	cachePath string
	extras    sync.Map // map[types.NamespacedName]*virtualizationGroupExtras
}

// NewVzClientAPIs initializes and returns a new VzClientAPIs instance.
func NewVzClientAPIs(ctx context.Context, eventRecorder event.EventRecorder, networkInterfaceIdentifier, cachePath, cniSocketPath string, dockerCl *docker.Client) (client *VzClientAPIs) {
	ctx, span := trace.StartSpan(ctx, "VZClient.NewVzClientAPIs")
	defer span.End()

	// force remove dangling mounts
	_ = os.RemoveAll(filepath.Join(cachePath, PodMountsDir))

	client = &VzClientAPIs{
		MacOSClient: rm.NewMacOSClient(ctx, eventRecorder, networkInterfaceIdentifier, cachePath),
		cachePath:   cachePath,
	}

	containerClient, err := rm.NewDockerClient(ctx, dockerCl, eventRecorder)
	if err != nil {
		log.G(ctx).WithError(err).Warn("Failed to create container client")
	}
	if containerClient != nil {
		client.ContainerClient = containerClient
	}

	hostProcessClient, err := rm.NewHostProcessClient(ctx)
	if err != nil {
		log.G(ctx).WithError(err).Warn("Failed to create host process client")
	}
	if hostProcessClient != nil {
		client.HostProcessClient = hostProcessClient
	}

	// Initialize CNI client if socket path is provided and available
	if cniSocketPath != "" && cni.IsAvailable(cniSocketPath) {
		cniClient, err := cni.NewClient(cniSocketPath)
		if err != nil {
			log.G(ctx).WithError(err).Warn("Failed to create CNI client")
		} else {
			client.CNIClient = cniClient
			log.G(ctx).Infof("CNI client connected to %s", cniSocketPath)
		}
	} else if cniSocketPath != "" {
		log.G(ctx).Warnf("CNI socket %s not available, VM pods will use internal IPs", cniSocketPath)
	}

	return client
}

// CreateVirtualizationGroup creates a new virtualization group based on the provided Kubernetes pod.
func (c *VzClientAPIs) CreateVirtualizationGroup(ctx context.Context, pod *corev1.Pod, serviceAccountToken string, configMaps map[string]*corev1.ConfigMap, creds resource.RegistryCredentialStore) (err error) {
	ctx, span := trace.StartSpan(ctx, "VZClient.CreateVirtualizationGroup")
	key := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	extras := &virtualizationGroupExtras{
		rootDir:    c.getPodVolumeRoot(pod),
		deleteDone: make(chan error, 1),
	}
	defer func() {
		span.SetStatus(err)
		span.End()

		// cleanup if an error occurred
		if err != nil {
			c.extras.Delete(key)
			if err := os.RemoveAll(extras.rootDir); err != nil {
				log.G(ctx).WithError(err).Warn("Failed to clean up pod volume root")
			}
			if extras.cancelFunc != nil {
				extras.cancelFunc()
			}
		}
	}()

	// If the pod has regular containers, the ContainerClient must be available.
	if len(pod.Spec.Containers) > 1 && c.ContainerClient == nil {
		return errdefs.InvalidInput("regular containers are not supported")
	}

	// Due to the nature of virtual kubelet CreatePod context,
	// we need to handle the context cancellation on demand ourselves
	ctx, extras.cancelFunc = context.WithCancel(ctx)

	// Store the extras for the virtualization group before doing any async work
	c.extras.Store(key, extras)

	g := errgroup.Group{}
	g.Go(func() error {
		// vz: always assume that first container is macOS container
		macOSContainer := pod.Spec.Containers[0]
		vmCreds, _ := creds.ForImage(macOSContainer.Image)

		// Extract and validate CPU and memory requests
		rl := macOSContainer.Resources.Requests
		cpu, err := utils.ExtractCPURequest(rl)
		if err != nil {
			return errdefs.AsInvalidInput(err)
		}
		_, err = vm.ValidateCPUCount(cpu)
		if err != nil {
			return errdefs.AsInvalidInput(err)
		}
		memorySize, err := utils.ExtractMemoryRequest(rl)
		if err != nil {
			return errdefs.AsInvalidInput(err)
		}
		_, err = vm.ValidateMemorySize(memorySize)
		if err != nil {
			return errdefs.AsInvalidInput(err)
		}

		mounts, err := volumes.CreateContainerMounts(ctx, extras.rootDir, macOSContainer, pod, serviceAccountToken, configMaps)
		if err != nil {
			return err
		}

		image := macOSContainer.Image
		pullPolicy := macOSContainer.ImagePullPolicy

		var postStartAction *resource.ExecAction
		if lifecycle := macOSContainer.Lifecycle; lifecycle != nil && lifecycle.PostStart != nil && lifecycle.PostStart.Exec != nil {
			postStartAction = &resource.ExecAction{
				Command:         lifecycle.PostStart.Exec.Command,
				TimeoutDuration: PostStartCommandTimeout,
			}
		}

		err = c.MacOSClient.CreateVirtualMachine(ctx, rm.VirtualMachineParams{
			UID:              string(pod.UID),
			Image:            image,
			Namespace:        pod.Namespace,
			Name:             pod.Name,
			ContainerName:    macOSContainer.Name,
			CPU:              cpu,
			MemorySize:       memorySize,
			Mounts:           mounts,
			Env:              macOSContainer.Env,
			PostStartAction:  postStartAction,
			IgnoreImageCache: pullPolicy == corev1.PullAlways,
			RegistryCreds:    vmCreds,
		})
		if err != nil {
			return err
		}

		// If CNI client is available, request a VPC IP for the VM
		if c.CNIClient != nil {
			vmInfo, ok := c.MacOSClient.GetVirtualMachineInfo(pod.Namespace, pod.Name)
			if ok && vmInfo.Resource.IPAddress() != "" {
				networkInfo, cniErr := c.CNIClient.AddNetwork(ctx, pod.Namespace, pod.Name, macOSContainer.Name, vmInfo.Resource.IPAddress())
				if cniErr != nil {
					log.G(ctx).WithError(cniErr).Warn("Failed to configure VPC networking, pod will use internal IP")
				} else {
					// Store the VPC IP in the VM info
					c.MacOSClient.SetVPCIPAddress(pod.Namespace, pod.Name, networkInfo.VPCIP)
					log.G(ctx).Infof("VPC IP assigned: %s -> %s", vmInfo.Resource.IPAddress(), networkInfo.VPCIP)
				}
			}
		}

		return nil
	})

	for i := 1; i < len(pod.Spec.Containers); i++ {
		container := pod.Spec.Containers[i]
		containerIndex := i
		g.Go(func() error {
			runtime := getContainerRuntime(pod, container.Name, containerIndex)

			// Handle host process runtime
			if runtime == resource.HostProcessRuntime {
				if c.HostProcessClient == nil {
					return errdefs.InvalidInput("host process runtime is not available")
				}

				mounts, err := volumes.CreateContainerMounts(ctx, extras.rootDir, container, pod, serviceAccountToken, configMaps)
				if err != nil {
					return err
				}

				return c.HostProcessClient.CreateProcess(
					ctx,
					rm.HostProcessParams{
						PodNamespace: pod.Namespace,
						PodName:      pod.Name,
						Name:         container.Name,
						Command:      container.Command,
						Args:         container.Args,
						Env:          container.Env,
						WorkingDir:   container.WorkingDir,
						Mounts:       mounts,
					},
				)
			}

			// Default: Docker container runtime
			containerCreds, _ := creds.ForImage(container.Image)

			mounts, err := volumes.CreateContainerMounts(ctx, extras.rootDir, container, pod, serviceAccountToken, configMaps)
			if err != nil {
				return err
			}

			var postStartAction *resource.ExecAction
			if lifecycle := container.Lifecycle; lifecycle != nil && lifecycle.PostStart != nil && lifecycle.PostStart.Exec != nil {
				postStartAction = &resource.ExecAction{
					Command:         lifecycle.PostStart.Exec.Command,
					TimeoutDuration: PostStartCommandTimeout,
				}
			}

			return c.ContainerClient.CreateContainer(
				ctx,
				rm.ContainerParams{
					PodNamespace:    pod.Namespace,
					PodName:         pod.Name,
					Name:            container.Name,
					Image:           container.Image,
					ImagePullPolicy: container.ImagePullPolicy,
					Mounts:          mounts,
					Env:             container.Env,
					Command:         container.Command,
					Args:            container.Args,
					WorkingDir:      container.WorkingDir,
					TTY:             container.TTY,
					Stdin:           container.Stdin,
					StdinOnce:       container.StdinOnce,
					PostStartAction: postStartAction,
					RegistryCreds:   containerCreds,
				},
			)
		})
	}

	return g.Wait()
}

// DeleteVirtualizationGroup deletes an existing virtualization group specified by namespace and name.
func (c *VzClientAPIs) DeleteVirtualizationGroup(ctx context.Context, namespace, name string, gracePeriod int64) (err error) {
	ctx, span := trace.StartSpan(ctx, "VZClient.DeleteVirtualizationGroup")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	key := types.NamespacedName{Namespace: namespace, Name: name}
	extrasValue, loaded := c.extras.Load(key)
	if !loaded {
		return errVirtualizationGroupNotFound
	}

	extras, ok := extrasValue.(*virtualizationGroupExtras)
	if !ok {
		return errVirtualizationGroupNotFound
	}

	// Initiate the deletion process only once
	extras.deleteOnce.Do(func() {
		defer func() {
			c.extras.Delete(key)
			close(extras.deleteDone)

			// Clean up the pod volume root directory and cancel the context
			if extras.cancelFunc != nil {
				// Group context must be cancelled after cleaning up all resources
				// related to Virtual Machine and Containers.
				extras.cancelFunc()
			}

			if extras.rootDir != "" {
				if err := os.RemoveAll(extras.rootDir); err != nil {
					log.G(ctx).WithError(err).Warn("Failed to clean up pod volume root")
				}
			}
		}()

		var wg sync.WaitGroup
		var vmErr, containerErr, hostProcessErr error

		// Delete virtual machine
		wg.Add(1)
		go func() {
			defer wg.Done()
			vmErr = c.MacOSClient.DeleteVirtualMachine(ctx, namespace, name, gracePeriod)
		}()

		// Delete containers
		if c.ContainerClient != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				containerErr = c.ContainerClient.RemoveContainers(ctx, namespace, name, gracePeriod)
			}()
		}

		// Delete host processes
		if c.HostProcessClient != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				hostProcessErr = c.HostProcessClient.RemoveProcesses(ctx, namespace, name, gracePeriod)
			}()
		}

		// Release VPC IP if CNI client is available
		if c.CNIClient != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Use empty container name - the CNI server tracks by namespace/podName
				if err := c.CNIClient.DelNetwork(ctx, namespace, name, ""); err != nil {
					log.G(ctx).WithError(err).Warn("Failed to release VPC IP")
				}
			}()
		}

		wg.Wait() // Wait for all operations to complete

		// Combine errors (excluding CNI errors which are non-fatal warnings)
		allErrs := []error{vmErr, containerErr, hostProcessErr}
		var nonNilErrs []error
		allNotFound := true
		for _, e := range allErrs {
			if e != nil {
				nonNilErrs = append(nonNilErrs, e)
				if !errdefs.IsNotFound(e) {
					allNotFound = false
				}
			}
		}

		switch {
		case len(nonNilErrs) == len(allErrs) && allNotFound:
			extras.deleteDone <- errVirtualizationGroupNotFound
		case len(nonNilErrs) > 0 && !allNotFound:
			extras.deleteDone <- errors.Join(nonNilErrs...)
		case vmErr != nil:
			if errdefs.IsNotFound(vmErr) {
				extras.deleteDone <- nil
			} else {
				extras.deleteDone <- vmErr
			}
		case containerErr != nil:
			if errdefs.IsNotFound(containerErr) {
				extras.deleteDone <- nil
			} else {
				extras.deleteDone <- containerErr
			}
		default:
			extras.deleteDone <- nil
		}
	})

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-extras.deleteDone:
		return err
	}
}

// GetVirtualizationGroup retrieves the details of a specified virtualization group.
func (c *VzClientAPIs) GetVirtualizationGroup(ctx context.Context, namespace, name string) (vg *VirtualizationGroup, err error) {
	ctx, span := trace.StartSpan(ctx, "VZClient.GetVirtualizationGroup")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	var containers []resource.Container
	var processes []resource.Process
	var vm resource.MacOSVirtualMachine
	var containerErr, vmErr, processErr error

	// Fetch containers
	if c.ContainerClient != nil {
		containers, containerErr = c.ContainerClient.GetContainers(ctx, namespace, name)
		if containerErr != nil && !errdefs.IsNotFound(containerErr) {
			err = containerErr
		}
	} else {
		containerErr = errdefs.NotFound("container client not available")
	}

	// Fetch host processes
	if c.HostProcessClient != nil {
		processes, processErr = c.HostProcessClient.GetProcesses(ctx, namespace, name)
		if processErr != nil && !errdefs.IsNotFound(processErr) {
			if err != nil {
				err = errors.Join(err, processErr)
			} else {
				err = processErr
			}
		}
	}

	// Fetch virtual machine
	vm, vmErr = c.MacOSClient.GetVirtualMachine(ctx, namespace, name)
	if vmErr != nil && !errdefs.IsNotFound(vmErr) {
		if err != nil {
			err = errors.Join(err, vmErr)
		} else {
			err = vmErr
		}
	}

	// If all clients return not found errors, return a combined not found error
	allNotFound := errdefs.IsNotFound(containerErr) && errdefs.IsNotFound(vmErr) &&
		(c.HostProcessClient == nil || errdefs.IsNotFound(processErr) || processErr == nil && len(processes) == 0)
	if allNotFound {
		return nil, errVirtualizationGroupNotFound
	}

	// Get VPC IP if available
	vpcIP := c.MacOSClient.GetVPCIPAddress(namespace, name)

	// Return the virtualization group with any existing values
	return &VirtualizationGroup{
		Containers:          containers,
		Processes:           processes,
		MacOSVirtualMachine: &vm,
		VPCIPAddress:        vpcIP,
	}, err
}

// GetVirtualizationGroupListResult retrieves a list of all virtualization groups.
func (c *VzClientAPIs) GetVirtualizationGroupListResult(ctx context.Context) (l map[types.NamespacedName]*VirtualizationGroup, err error) {
	ctx, span := trace.StartSpan(ctx, "VZClient.GetVirtualizationGroupListResult")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()
	logger := log.G(ctx)

	var wg sync.WaitGroup
	var vmErr, containerErr, processErr error
	var vms map[types.NamespacedName]resource.MacOSVirtualMachine
	var containers map[types.NamespacedName][]resource.Container
	var processes map[types.NamespacedName][]resource.Process

	// Fetch virtual machines
	wg.Add(1)
	go func() {
		defer wg.Done()
		vms, vmErr = c.MacOSClient.GetVirtualMachineListResult(ctx)
		if vmErr != nil {
			logger.WithError(vmErr).Warn("Error getting VM list")
		}
	}()

	// Fetch containers
	if c.ContainerClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			containers, containerErr = c.ContainerClient.GetContainersListResult(ctx)
			if containerErr != nil {
				logger.WithError(containerErr).Warn("Error getting container list")
			}
		}()
	}

	// Fetch host processes
	if c.HostProcessClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processes, processErr = c.HostProcessClient.GetProcessesListResult(ctx)
			if processErr != nil {
				logger.WithError(processErr).Warn("Error getting host process list")
			}
		}()
	}

	wg.Wait()

	// Combine errors
	var errs []error
	if vmErr != nil {
		errs = append(errs, vmErr)
	}
	if containerErr != nil {
		errs = append(errs, containerErr)
	}
	if processErr != nil {
		errs = append(errs, processErr)
	}
	if len(errs) > 0 {
		err = errors.Join(errs...)
	}

	// Initialize the result map
	l = make(map[types.NamespacedName]*VirtualizationGroup)

	// Combine the results
	for k, v := range vms {
		vpcIP := c.MacOSClient.GetVPCIPAddress(k.Namespace, k.Name)
		l[k] = &VirtualizationGroup{
			MacOSVirtualMachine: &v,
			VPCIPAddress:        vpcIP,
		}
	}

	for k, c := range containers {
		if vg, exists := l[k]; exists {
			vg.Containers = c
		} else {
			l[k] = &VirtualizationGroup{
				Containers: c,
			}
		}
	}

	for k, p := range processes {
		if vg, exists := l[k]; exists {
			vg.Processes = p
		} else {
			l[k] = &VirtualizationGroup{
				Processes: p,
			}
		}
	}

	return l, err
}

// GetContainerLogs retrieves the logs of a specified container in the virtualization group.
func (c *VzClientAPIs) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts api.ContainerLogOpts) (in io.ReadCloser, err error) {
	ctx, span := trace.StartSpan(ctx, "VZClient.GetContainerLogs")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	// Check host processes first
	if c.HostProcessClient != nil && c.HostProcessClient.IsProcessPresent(ctx, namespace, podName, containerName) {
		return c.HostProcessClient.GetProcessLogs(ctx, namespace, podName, containerName, opts)
	}

	// Check containers
	if c.ContainerClient != nil && c.ContainerClient.IsContainerPresent(ctx, namespace, podName, containerName) {
		return c.ContainerClient.GetContainerLogs(ctx, namespace, podName, containerName, opts)
	}

	return nil, errdefs.InvalidInput("container logs are not supported for macOS virtual machines")
}

// ExecuteContainerCommand executes a command inside a specified container.
func (c *VzClientAPIs) ExecuteContainerCommand(ctx context.Context, namespace, podName, containerName string, cmd []string, attach api.AttachIO) (err error) {
	ctx, span := trace.StartSpan(ctx, "VZClient.ExecuteContainerCommand")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	// Check host processes first
	if c.HostProcessClient != nil && c.HostProcessClient.IsProcessPresent(ctx, namespace, podName, containerName) {
		return c.HostProcessClient.ExecInProcess(ctx, namespace, podName, containerName, cmd, attach)
	}

	// Check containers
	if c.ContainerClient != nil && c.ContainerClient.IsContainerPresent(ctx, namespace, podName, containerName) {
		return c.ContainerClient.ExecInContainer(ctx, namespace, podName, containerName, cmd, attach)
	}

	return c.MacOSClient.ExecInVirtualMachine(ctx, namespace, podName, cmd, attach)
}

// AttachToContainer attaches to a specified container.
func (c *VzClientAPIs) AttachToContainer(ctx context.Context, namespace, podName, containerName string, attach api.AttachIO) (err error) {
	ctx, span := trace.StartSpan(ctx, "VZClient.AttachToContainer")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	if c.ContainerClient != nil && c.ContainerClient.IsContainerPresent(ctx, namespace, podName, containerName) {
		return c.ContainerClient.AttachToContainer(ctx, namespace, podName, containerName, attach)
	}

	return c.MacOSClient.ExecInVirtualMachine(ctx, namespace, podName, nil, attach)
}

func (c *VzClientAPIs) GetVirtualizationGroupStats(ctx context.Context, namespace, name string, containers []corev1.Container) (cs []stats.ContainerStats, err error) {
	ctx, span := trace.StartSpan(ctx, "VZClient.GetVirtualizationGroupStats")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	vmStats, err := c.MacOSClient.GetVirtualMachineStats(ctx, namespace, name)
	if err != nil {
		return nil, err
	}

	// vz: always assume that first container is macOS container
	vmStats.Name = containers[0].Name
	cs = append(cs, vmStats)

	for _, container := range containers[1:] {
		containerStats, err := c.ContainerClient.GetContainerStats(ctx, namespace, name, container.Name)
		if err != nil {
			return nil, err
		}
		cs = append(cs, containerStats)
	}

	return cs, nil
}

// getPodVolumeRoot returns the root path for the volumes of a pod
func (c *VzClientAPIs) getPodVolumeRoot(pod *corev1.Pod) string {
	return filepath.Join(c.cachePath, PodMountsDir, string(pod.UID))
}

// getContainerRuntime determines the runtime for a container based on pod annotations.
// For the first container (index 0), default is MacOSRuntime ("vz").
// For other containers, default is ContainerRuntime ("docker").
// Runtime can be overridden via annotation: vz.kubernetes.io/runtime.<container-name>=<runtime>
func getContainerRuntime(pod *corev1.Pod, containerName string, containerIndex int) string {
	// Check for container-specific annotation
	annotationKey := resource.RuntimeAnnotationPrefix + containerName
	if runtime, ok := pod.Annotations[annotationKey]; ok {
		return runtime
	}

	// Default based on container index
	if containerIndex == 0 {
		return resource.MacOSRuntime
	}
	return resource.ContainerRuntime
}
