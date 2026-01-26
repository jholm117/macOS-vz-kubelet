package cni_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agoda-com/macOS-vz-kubelet/pkg/cni"
	pb "github.com/agoda-com/macOS-vz-kubelet/pkg/cni/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestIsAvailable_NonExistentSocket(t *testing.T) {
	// Non-existent socket should return false
	available := cni.IsAvailable("/nonexistent/path/to/socket.sock")
	assert.False(t, available)
}

func TestIsAvailable_ExistingSocket(t *testing.T) {
	// Create a mock gRPC server on a Unix socket
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	server := grpc.NewServer()
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Stop()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// The socket should be available
	available := cni.IsAvailable(socketPath)
	assert.True(t, available)
}

func TestNewClient_NonExistentSocket(t *testing.T) {
	// Creating a client with a non-existent socket should fail
	_, err := cni.NewClient("/nonexistent/path/to/socket.sock")
	assert.Error(t, err)
}

func TestNewClient_ExistingSocket(t *testing.T) {
	// Create a mock gRPC server on a Unix socket
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	server := grpc.NewServer()
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Stop()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Creating a client should succeed
	client, err := cni.NewClient(socketPath)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()
}

func TestAddNetwork_InvalidIP(t *testing.T) {
	// Create a mock gRPC server
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	server := grpc.NewServer()
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := cni.NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	// AddNetwork with invalid IP should fail
	ctx := context.Background()
	_, err = client.AddNetwork(ctx, "default", "pod", "container", "invalid-ip")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid VM internal IP")
}

// MockCNIService is a mock implementation of the CNI service for testing
type MockCNIService struct {
	pb.UnimplementedCNIServiceServer
	addNetworkResponse *pb.AddNetworkResponse
	addNetworkError    error
	delNetworkError    error
	getNetworkResponse *pb.GetNetworkInfoResponse
	getNetworkError    error
}

func (m *MockCNIService) AddNetwork(ctx context.Context, req *pb.AddNetworkRequest) (*pb.AddNetworkResponse, error) {
	if m.addNetworkError != nil {
		return nil, m.addNetworkError
	}
	if m.addNetworkResponse != nil {
		return m.addNetworkResponse, nil
	}
	return &pb.AddNetworkResponse{
		VpcIp:             "10.0.1.100",
		SubnetMask:        "255.255.255.0",
		Gateway:           "10.0.1.1",
		RoutingConfigured: true,
	}, nil
}

func (m *MockCNIService) DelNetwork(ctx context.Context, req *pb.DelNetworkRequest) (*pb.DelNetworkResponse, error) {
	if m.delNetworkError != nil {
		return nil, m.delNetworkError
	}
	return &pb.DelNetworkResponse{}, nil
}

func (m *MockCNIService) GetNetworkInfo(ctx context.Context, req *pb.GetNetworkInfoRequest) (*pb.GetNetworkInfoResponse, error) {
	if m.getNetworkError != nil {
		return nil, m.getNetworkError
	}
	if m.getNetworkResponse != nil {
		return m.getNetworkResponse, nil
	}
	return &pb.GetNetworkInfoResponse{
		VpcIp:             "10.0.1.100",
		RoutingConfigured: true,
	}, nil
}

func setupMockServer(t *testing.T, service *MockCNIService) (string, func()) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "cni.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	server := grpc.NewServer()
	pb.RegisterCNIServiceServer(server, service)

	go func() {
		_ = server.Serve(listener)
	}()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		server.Stop()
		listener.Close()
		os.Remove(socketPath)
	}

	return socketPath, cleanup
}

func TestAddNetwork_Success(t *testing.T) {
	mockService := &MockCNIService{}
	socketPath, cleanup := setupMockServer(t, mockService)
	defer cleanup()

	client, err := cni.NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	networkInfo, err := client.AddNetwork(ctx, "default", "test-pod", "test-container", "192.168.64.5")
	require.NoError(t, err)
	require.NotNil(t, networkInfo)
	assert.Equal(t, "10.0.1.100", networkInfo.VPCIP)
	assert.Equal(t, "255.255.255.0", networkInfo.SubnetMask)
	assert.Equal(t, "10.0.1.1", networkInfo.Gateway)
	assert.True(t, networkInfo.RoutingConfigured)
}

func TestDelNetwork_Success(t *testing.T) {
	mockService := &MockCNIService{}
	socketPath, cleanup := setupMockServer(t, mockService)
	defer cleanup()

	client, err := cni.NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.DelNetwork(ctx, "default", "test-pod", "test-container")
	require.NoError(t, err)
}

func TestGetNetworkInfo_Success(t *testing.T) {
	mockService := &MockCNIService{}
	socketPath, cleanup := setupMockServer(t, mockService)
	defer cleanup()

	client, err := cni.NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	networkInfo, err := client.GetNetworkInfo(ctx, "default", "test-pod", "test-container")
	require.NoError(t, err)
	require.NotNil(t, networkInfo)
	assert.Equal(t, "10.0.1.100", networkInfo.VPCIP)
	assert.True(t, networkInfo.RoutingConfigured)
}

func TestGetNetworkInfo_NotAllocated(t *testing.T) {
	mockService := &MockCNIService{
		getNetworkResponse: &pb.GetNetworkInfoResponse{
			VpcIp: "", // Not allocated
		},
	}
	socketPath, cleanup := setupMockServer(t, mockService)
	defer cleanup()

	client, err := cni.NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	networkInfo, err := client.GetNetworkInfo(ctx, "default", "test-pod", "test-container")
	require.NoError(t, err)
	assert.Nil(t, networkInfo) // Returns nil when not allocated
}
