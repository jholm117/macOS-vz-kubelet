package vm_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/agoda-com/macOS-vz-kubelet/internal/data/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

func TestGetVirtualMachineInfo(t *testing.T) {
	d := vm.VirtualMachineData{}
	namespace := "default"
	podName := "pod1"
	info := vm.VirtualMachineInfo{Ref: "vm1"}

	// Initially, the info should not be found
	_, found := d.GetVirtualMachineInfo(namespace, podName)
	assert.False(t, found)

	// Set the info and then retrieve it
	_, loaded := d.GetOrCreateVirtualMachineInfo(namespace, podName, info)
	assert.False(t, loaded)
	retrievedInfo, found := d.GetVirtualMachineInfo(namespace, podName)
	assert.True(t, found)
	assert.Equal(t, info, retrievedInfo)
}

func TestUpdateVirtualMachineInfo(t *testing.T) {
	d := vm.VirtualMachineData{}
	namespace := "default"
	podName := "pod1"
	initialInfo := vm.VirtualMachineInfo{Ref: "vm1"}
	updatedInfo := vm.VirtualMachineInfo{Ref: "vm2"}

	// Initially, the info should not be found
	_, found := d.UpdateVirtualMachineInfo(namespace, podName, func(info vm.VirtualMachineInfo) vm.VirtualMachineInfo {
		return updatedInfo
	})
	assert.False(t, found)

	// Set the info, update it, and then retrieve the updated info
	_, loaded := d.GetOrCreateVirtualMachineInfo(namespace, podName, initialInfo)
	assert.False(t, loaded)
	retrievedInfo, found := d.UpdateVirtualMachineInfo(namespace, podName, func(info vm.VirtualMachineInfo) vm.VirtualMachineInfo {
		return updatedInfo
	})
	assert.True(t, found)
	assert.Equal(t, updatedInfo, retrievedInfo)
}

func TestGetOrCreateVirtualMachineInfo(t *testing.T) {
	d := vm.VirtualMachineData{}
	namespace := "default"
	podName := "pod1"
	info := vm.VirtualMachineInfo{Ref: "vm1"}

	// Initially, the info should be created
	retrievedInfo, found := d.GetOrCreateVirtualMachineInfo(namespace, podName, info)
	assert.False(t, found)
	assert.Equal(t, info, retrievedInfo)

	// The info should now exist
	retrievedInfo, found = d.GetOrCreateVirtualMachineInfo(namespace, podName, vm.VirtualMachineInfo{Ref: "vm2"})
	assert.True(t, found)
	assert.Equal(t, info, retrievedInfo)
}

func TestRemoveVirtualMachineInfo(t *testing.T) {
	d := vm.VirtualMachineData{}
	namespace := "default"
	podName := "pod1"
	info := vm.VirtualMachineInfo{Ref: "vm1"}

	_, loaded := d.GetOrCreateVirtualMachineInfo(namespace, podName, info)
	assert.False(t, loaded)
	d.RemoveVirtualMachineInfo(namespace, podName)
	_, found := d.GetVirtualMachineInfo(namespace, podName)
	assert.False(t, found)
}

func TestCount(t *testing.T) {
	d := vm.VirtualMachineData{}
	assert.Equal(t, int32(0), d.Count())

	_, loaded := d.GetOrCreateVirtualMachineInfo("default", "pod1", vm.VirtualMachineInfo{Ref: "vm1"})
	assert.False(t, loaded)
	assert.Equal(t, int32(1), d.Count())

	_, loaded = d.GetOrCreateVirtualMachineInfo("default", "pod2", vm.VirtualMachineInfo{Ref: "vm2"})
	assert.False(t, loaded)
	assert.Equal(t, int32(2), d.Count())

	d.RemoveVirtualMachineInfo("default", "pod1")
	assert.Equal(t, int32(1), d.Count())
}

func TestListVirtualMachines(t *testing.T) {
	d := vm.VirtualMachineData{}
	vm1 := vm.VirtualMachineInfo{Ref: "vm1"}
	vm2 := vm.VirtualMachineInfo{Ref: "vm2"}

	_, loaded := d.GetOrCreateVirtualMachineInfo("default", "pod1", vm1)
	assert.False(t, loaded)
	_, loaded = d.GetOrCreateVirtualMachineInfo("default", "pod2", vm2)
	assert.False(t, loaded)

	vms := d.ListVirtualMachines()
	require.Len(t, vms, 2)
	assert.Equal(t, vm1, vms[types.NamespacedName{Namespace: "default", Name: "pod1"}])
	assert.Equal(t, vm2, vms[types.NamespacedName{Namespace: "default", Name: "pod2"}])
}

func TestConcurrentAccess(t *testing.T) {
	d := vm.VirtualMachineData{}
	var wg sync.WaitGroup
	namespace := "default"
	numRoutines := 100

	// Create and start multiple goroutines to test concurrent access
	for i := range numRoutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			podName := fmt.Sprintf("pod%d", i)
			info := vm.VirtualMachineInfo{Ref: fmt.Sprintf("vm%d", i)}
			_, loaded := d.GetOrCreateVirtualMachineInfo(namespace, podName, info)
			assert.False(t, loaded)
		}(i)
	}

	wg.Wait()

	// Verify the count after concurrent operations
	assert.Equal(t, int32(numRoutines), d.Count())

	// Verify each virtual machine info was set correctly
	for i := range numRoutines {
		podName := fmt.Sprintf("pod%d", i)
		info, found := d.GetVirtualMachineInfo(namespace, podName)
		assert.True(t, found)
		assert.Equal(t, fmt.Sprintf("vm%d", i), info.Ref)
	}
}

func TestSetVPCIPAddress(t *testing.T) {
	d := vm.VirtualMachineData{}
	namespace := "default"
	podName := "pod1"
	info := vm.VirtualMachineInfo{Ref: "vm1"}

	// Setting VPC IP on non-existent VM should return false
	ok := d.SetVPCIPAddress(namespace, podName, "10.0.1.100")
	assert.False(t, ok)

	// Create the VM
	_, loaded := d.GetOrCreateVirtualMachineInfo(namespace, podName, info)
	assert.False(t, loaded)

	// Now setting VPC IP should succeed
	ok = d.SetVPCIPAddress(namespace, podName, "10.0.1.100")
	assert.True(t, ok)

	// Verify the VPC IP was set
	retrievedInfo, found := d.GetVirtualMachineInfo(namespace, podName)
	assert.True(t, found)
	assert.Equal(t, "10.0.1.100", retrievedInfo.VPCIPAddress)
}

func TestGetVPCIPAddress(t *testing.T) {
	d := vm.VirtualMachineData{}
	namespace := "default"
	podName := "pod1"

	// Getting VPC IP for non-existent VM should return empty string
	vpcIP := d.GetVPCIPAddress(namespace, podName)
	assert.Equal(t, "", vpcIP)

	// Create VM without VPC IP
	info := vm.VirtualMachineInfo{Ref: "vm1"}
	_, loaded := d.GetOrCreateVirtualMachineInfo(namespace, podName, info)
	assert.False(t, loaded)

	// VPC IP should be empty
	vpcIP = d.GetVPCIPAddress(namespace, podName)
	assert.Equal(t, "", vpcIP)

	// Set VPC IP and verify
	d.SetVPCIPAddress(namespace, podName, "10.0.1.100")
	vpcIP = d.GetVPCIPAddress(namespace, podName)
	assert.Equal(t, "10.0.1.100", vpcIP)
}

func TestVPCIPAddressConcurrentAccess(t *testing.T) {
	d := vm.VirtualMachineData{}
	namespace := "default"
	podName := "pod1"
	info := vm.VirtualMachineInfo{Ref: "vm1"}

	// Create the VM
	_, loaded := d.GetOrCreateVirtualMachineInfo(namespace, podName, info)
	assert.False(t, loaded)

	var wg sync.WaitGroup
	numRoutines := 50

	// Concurrent writes to VPC IP
	for i := range numRoutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			vpcIP := fmt.Sprintf("10.0.1.%d", i)
			d.SetVPCIPAddress(namespace, podName, vpcIP)
		}(i)
	}

	wg.Wait()

	// VPC IP should be set to one of the values (last writer wins)
	vpcIP := d.GetVPCIPAddress(namespace, podName)
	assert.NotEmpty(t, vpcIP)
	assert.Contains(t, vpcIP, "10.0.1.")
}
