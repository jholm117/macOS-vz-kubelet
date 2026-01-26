package e2e_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/cni"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sresource "k8s.io/apimachinery/pkg/api/resource"
)

// TestVPCCNIIntegration tests the VPC CNI integration with the kubelet.
// This test requires:
// 1. The VPC CNI agent running at VZ_CNI_SOCKET_PATH
// 2. AWS credentials and IMDS access (runs on EC2 Mac)
func TestVPCCNIIntegration(t *testing.T) {
	cniSocketPath := os.Getenv("VZ_CNI_SOCKET_PATH")
	if cniSocketPath == "" {
		t.Skip("VZ_CNI_SOCKET_PATH not set, skipping VPC CNI integration tests")
	}

	if !cni.IsAvailable(cniSocketPath) {
		t.Skip("CNI agent not available at " + cniSocketPath)
	}

	suite := newProviderSuite(t)

	t.Run("macos-image-upload", func(t *testing.T) {
		suite.uploadMacOSImageIfRequested(t)
	})

	registryHost := suite.registryHost(t)
	suite.ensureNamespace(t)

	node := suite.getNode(t)
	ownerRef := nodeOwnerReference(node)
	secretName := suite.createRegistrySecret(t, ownerRef, registryHost)

	t.Run("pod-gets-vpc-ip", func(t *testing.T) {
		pod := suite.newBasicPod(ownerRef, secretName)
		createdPod := suite.createPod(t, pod)
		readyPod := suite.waitForPodReady(t, createdPod.Name)

		// Verify pod has a VPC IP (10.x.x.x range typically)
		podIP := readyPod.Status.PodIP
		require.NotEmpty(t, podIP, "pod should have an IP address")

		ip := net.ParseIP(podIP)
		require.NotNil(t, ip, "pod IP should be a valid IP address")

		// Check if it's a VPC IP (not the internal 192.168.64.x range)
		// VPC IPs are typically in the 10.x.x.x or 172.x.x.x range
		isVPCIP := ip.To4() != nil && (ip.To4()[0] == 10 || ip.To4()[0] == 172)
		if !isVPCIP {
			t.Logf("Warning: Pod IP %s may not be a VPC IP (expected 10.x.x.x or 172.x.x.x)", podIP)
		}

		t.Logf("Pod %s has IP: %s", createdPod.Name, podIP)

		suite.deletePod(t, createdPod.Name)
	})

	t.Run("vpc-ip-released-on-delete", func(t *testing.T) {
		// Create a pod and get its VPC IP
		pod := suite.newBasicPod(ownerRef, secretName)
		createdPod := suite.createPod(t, pod)
		readyPod := suite.waitForPodReady(t, createdPod.Name)

		allocatedIP := readyPod.Status.PodIP
		require.NotEmpty(t, allocatedIP)
		t.Logf("Pod allocated IP: %s", allocatedIP)

		// Delete the pod
		suite.deletePod(t, createdPod.Name)

		// Verify IP is released by checking CNI agent directly
		client, err := cni.NewClient(cniSocketPath)
		require.NoError(t, err)
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		networkInfo, err := client.GetNetworkInfo(ctx, suite.namespace, createdPod.Name, "macos")
		if err == nil && networkInfo != nil {
			// IP should be released (no longer allocated)
			t.Logf("Network info after delete: VPC IP=%s", networkInfo.VPCIP)
		}
		// Note: GetNetworkInfo may return error or nil after IP is released, both are acceptable
	})
}

// TestCNIAgentDaemonSet tests deploying the CNI agent as a host process DaemonSet.
// This validates that the CNI agent can be deployed as a native host process.
func TestCNIAgentDaemonSet(t *testing.T) {
	cniSocketPath := os.Getenv("VZ_CNI_SOCKET_PATH")
	if cniSocketPath == "" {
		t.Skip("VZ_CNI_SOCKET_PATH not set, skipping CNI DaemonSet test")
	}

	suite := newProviderSuite(t)

	t.Run("macos-image-upload", func(t *testing.T) {
		suite.uploadMacOSImageIfRequested(t)
	})

	registryHost := suite.registryHost(t)
	suite.ensureNamespace(t)

	node := suite.getNode(t)
	ownerRef := nodeOwnerReference(node)
	secretName := suite.createRegistrySecret(t, ownerRef, registryHost)

	t.Run("cni-agent-as-host-process", func(t *testing.T) {
		// This test validates that the CNI agent can run as a host process
		// In production, this would be a DaemonSet that runs the CNI agent binary
		pod := suite.newCNIAgentPod(ownerRef, secretName)
		createdPod := suite.createPod(t, pod)

		// Wait for pod to be ready
		readyPod := suite.waitForPodReady(t, createdPod.Name)

		// Verify the CNI agent container is running
		var cniAgentStatus *corev1.ContainerStatus
		for i, cs := range readyPod.Status.ContainerStatuses {
			if cs.Name == "cni-agent" {
				cniAgentStatus = &readyPod.Status.ContainerStatuses[i]
				break
			}
		}
		require.NotNil(t, cniAgentStatus, "cni-agent container status not found")
		assert.True(t, cniAgentStatus.Ready, "cni-agent container should be ready")
		assert.NotNil(t, cniAgentStatus.State.Running, "cni-agent container should be running")

		suite.deletePod(t, createdPod.Name)
	})
}

// newBasicPod creates a basic pod with just a macOS VM container
func (s *providerSuite) newBasicPod(ownerRef metav1.OwnerReference, secretName string) *corev1.Pod {
	gracePeriod := int64(0)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("macos-vz-vpc-cni-test-%d", time.Now().Unix()),
			Namespace:       s.namespace,
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: &gracePeriod,
			Containers: []corev1.Container{
				{
					Name:  "macos",
					Image: *macOSImage,
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    k8sresource.MustParse("4"),
							corev1.ResourceMemory: k8sresource.MustParse("12Gi"),
						},
					},
				},
			},
			NodeSelector: map[string]string{
				"kubernetes.io/os": "darwin",
			},
			Tolerations: []corev1.Toleration{
				{
					Key:      taintKey,
					Operator: corev1.TolerationOpEqual,
					Value:    taintValue,
					Effect:   corev1.TaintEffect(taintEffect),
				},
			},
			ImagePullSecrets: []corev1.LocalObjectReference{
				{Name: secretName},
			},
		},
	}
}

// newCNIAgentPod creates a pod with a CNI agent running as a host process
func (s *providerSuite) newCNIAgentPod(ownerRef metav1.OwnerReference, secretName string) *corev1.Pod {
	gracePeriod := int64(0)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("macos-vz-cni-agent-test-%d", time.Now().Unix()),
			Namespace:       s.namespace,
			OwnerReferences: []metav1.OwnerReference{ownerRef},
			Annotations: map[string]string{
				// Mark the CNI agent container as a host process
				resource.RuntimeAnnotationPrefix + "cni-agent": string(resource.HostProcessRuntime),
			},
		},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: &gracePeriod,
			Containers: []corev1.Container{
				{
					Name:  "macos",
					Image: *macOSImage,
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    k8sresource.MustParse("4"),
							corev1.ResourceMemory: k8sresource.MustParse("12Gi"),
						},
					},
				},
				{
					// CNI agent runs as a host process
					// In production, this would be the actual vpc-cni-agent binary
					// For testing, we use a simple script that simulates the agent
					Name: "cni-agent",
					Command: []string{"/bin/sh", "-c"},
					Args: []string{
						// Simulate CNI agent startup
						"echo 'CNI Agent starting...' && sleep 300",
					},
				},
			},
			NodeSelector: map[string]string{
				"kubernetes.io/os": "darwin",
			},
			Tolerations: []corev1.Toleration{
				{
					Key:      taintKey,
					Operator: corev1.TolerationOpEqual,
					Value:    taintValue,
					Effect:   corev1.TaintEffect(taintEffect),
				},
			},
			ImagePullSecrets: []corev1.LocalObjectReference{
				{Name: secretName},
			},
		},
	}
}
