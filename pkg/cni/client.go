package cni

import (
	"context"
	"fmt"
	"net"
	"time"

	pb "github.com/agoda-com/macOS-vz-kubelet/pkg/cni/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client provides access to the VPC CNI agent.
type Client struct {
	conn   *grpc.ClientConn
	client pb.CNIServiceClient
}

// NetworkInfo contains the network configuration for a VM.
type NetworkInfo struct {
	VPCIP             string
	SubnetMask        string
	Gateway           string
	RoutingConfigured bool
}

// NewClient creates a new CNI client connected to the agent.
func NewClient(socketPath string) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to the Unix socket
	conn, err := grpc.DialContext(ctx, "unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CNI agent at %s: %w", socketPath, err)
	}

	return &Client{
		conn:   conn,
		client: pb.NewCNIServiceClient(conn),
	}, nil
}

// AddNetwork requests a VPC IP for a VM and configures routing.
func (c *Client) AddNetwork(ctx context.Context, namespace, podName, containerName, vmInternalIP string) (*NetworkInfo, error) {
	// Validate VM internal IP
	if net.ParseIP(vmInternalIP) == nil {
		return nil, fmt.Errorf("invalid VM internal IP: %s", vmInternalIP)
	}

	resp, err := c.client.AddNetwork(ctx, &pb.AddNetworkRequest{
		Namespace:     namespace,
		PodName:       podName,
		ContainerName: containerName,
		VmInternalIp:  vmInternalIP,
	})
	if err != nil {
		return nil, fmt.Errorf("AddNetwork failed: %w", err)
	}

	return &NetworkInfo{
		VPCIP:             resp.VpcIp,
		SubnetMask:        resp.SubnetMask,
		Gateway:           resp.Gateway,
		RoutingConfigured: resp.RoutingConfigured,
	}, nil
}

// DelNetwork releases a VPC IP and removes routing configuration.
func (c *Client) DelNetwork(ctx context.Context, namespace, podName, containerName string) error {
	_, err := c.client.DelNetwork(ctx, &pb.DelNetworkRequest{
		Namespace:     namespace,
		PodName:       podName,
		ContainerName: containerName,
	})
	if err != nil {
		return fmt.Errorf("DelNetwork failed: %w", err)
	}
	return nil
}

// GetNetworkInfo retrieves the current network configuration for a VM.
func (c *Client) GetNetworkInfo(ctx context.Context, namespace, podName, containerName string) (*NetworkInfo, error) {
	resp, err := c.client.GetNetworkInfo(ctx, &pb.GetNetworkInfoRequest{
		Namespace:     namespace,
		PodName:       podName,
		ContainerName: containerName,
	})
	if err != nil {
		return nil, fmt.Errorf("GetNetworkInfo failed: %w", err)
	}

	if resp.VpcIp == "" {
		return nil, nil // Not allocated
	}

	return &NetworkInfo{
		VPCIP:             resp.VpcIp,
		RoutingConfigured: resp.RoutingConfigured,
	}, nil
}

// Close closes the connection to the CNI agent.
func (c *Client) Close() error {
	return c.conn.Close()
}

// IsAvailable checks if the CNI agent is available at the given socket path.
func IsAvailable(socketPath string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
