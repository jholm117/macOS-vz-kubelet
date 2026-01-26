package resourcemanager_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/resourcemanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// Check that HostProcess implements the HostProcessClient interface
var _ resourcemanager.HostProcessClient = &resourcemanager.HostProcess{}

func TestNewHostProcessClient(t *testing.T) {
	ctx := context.Background()

	// Create a temp directory for logs
	tempDir := t.TempDir()
	origLogDir := resourcemanager.HostProcessLogDir

	// Note: We can't easily override the log directory constant,
	// but we can test that the client is created successfully
	client, err := resourcemanager.NewHostProcessClient(ctx)
	if err != nil {
		// If we can't create the log directory, skip the test
		t.Skipf("Cannot create host process client (may need root): %v", err)
	}
	require.NotNil(t, client)

	// Clean up
	_ = origLogDir
	_ = tempDir
}

func TestHostProcessCreateProcess_EmptyCommand(t *testing.T) {
	ctx := context.Background()

	client, err := resourcemanager.NewHostProcessClient(ctx)
	if err != nil {
		t.Skipf("Cannot create host process client: %v", err)
	}

	// Creating a process without a command should fail
	err = client.CreateProcess(ctx, resourcemanager.HostProcessParams{
		PodNamespace: "default",
		PodName:      "test-pod",
		Name:         "test-container",
		Command:      []string{}, // Empty command
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "command is required")
}

func TestHostProcessCreateAndGetProcess(t *testing.T) {
	ctx := context.Background()

	client, err := resourcemanager.NewHostProcessClient(ctx)
	if err != nil {
		t.Skipf("Cannot create host process client: %v", err)
	}

	namespace := "default"
	podName := "test-pod"
	containerName := "test-container"

	// Create a simple process that sleeps
	err = client.CreateProcess(ctx, resourcemanager.HostProcessParams{
		PodNamespace: namespace,
		PodName:      podName,
		Name:         containerName,
		Command:      []string{"/bin/sleep", "30"},
	})
	require.NoError(t, err)

	// Give the process time to start
	time.Sleep(100 * time.Millisecond)

	// Verify the process is present
	assert.True(t, client.IsProcessPresent(ctx, namespace, podName, containerName))

	// Get the process
	processes, err := client.GetProcesses(ctx, namespace, podName)
	require.NoError(t, err)
	require.Len(t, processes, 1)
	assert.Equal(t, containerName, processes[0].Name)

	// Clean up - remove the process
	err = client.RemoveProcesses(ctx, namespace, podName, 0)
	require.NoError(t, err)

	// Verify the process is no longer present
	time.Sleep(100 * time.Millisecond)
	assert.False(t, client.IsProcessPresent(ctx, namespace, podName, containerName))
}

func TestHostProcessWithEnvironment(t *testing.T) {
	ctx := context.Background()

	client, err := resourcemanager.NewHostProcessClient(ctx)
	if err != nil {
		t.Skipf("Cannot create host process client: %v", err)
	}

	namespace := "default"
	podName := "env-test-pod"
	containerName := "env-test-container"

	// Create a process that echoes an environment variable
	tempFile := filepath.Join(t.TempDir(), "env-output.txt")
	err = client.CreateProcess(ctx, resourcemanager.HostProcessParams{
		PodNamespace: namespace,
		PodName:      podName,
		Name:         containerName,
		Command:      []string{"/bin/sh", "-c", "echo $TEST_VAR > " + tempFile},
		Env: []corev1.EnvVar{
			{Name: "TEST_VAR", Value: "hello-world"},
		},
	})
	require.NoError(t, err)

	// Wait for the process to complete
	time.Sleep(500 * time.Millisecond)

	// Check the output file
	content, err := os.ReadFile(tempFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "hello-world")

	// Clean up
	_ = client.RemoveProcesses(ctx, namespace, podName, 0)
}

func TestHostProcessGetProcesses_NotFound(t *testing.T) {
	ctx := context.Background()

	client, err := resourcemanager.NewHostProcessClient(ctx)
	if err != nil {
		t.Skipf("Cannot create host process client: %v", err)
	}

	// Getting processes for non-existent pod should return not found error
	_, err = client.GetProcesses(ctx, "nonexistent", "pod")
	assert.Error(t, err)
}

func TestHostProcessIsProcessPresent(t *testing.T) {
	ctx := context.Background()

	client, err := resourcemanager.NewHostProcessClient(ctx)
	if err != nil {
		t.Skipf("Cannot create host process client: %v", err)
	}

	// Non-existent process should return false
	assert.False(t, client.IsProcessPresent(ctx, "nonexistent", "pod", "container"))
}
