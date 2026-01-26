package hostprocess

import (
	"sync"

	"k8s.io/apimachinery/pkg/types"
)

// ProcessData is a thread-safe map to store process information, indexed by NamespacedName and process name.
type ProcessData struct {
	data sync.Map // map[types.NamespacedName]map[string]*ProcessInfo (podNamespace/podName -> processName -> ProcessInfo)
}

// GetProcessInfo retrieves the ProcessInfo for a specific process within a specific pod.
// It returns the ProcessInfo and a boolean indicating whether the process information was found.
func (d *ProcessData) GetProcessInfo(podNamespace, podName, processName string) (*ProcessInfo, bool) {
	key := types.NamespacedName{Namespace: podNamespace, Name: podName}
	val, ok := d.data.Load(key)
	if !ok {
		return nil, false
	}
	infoval, ok := val.(*sync.Map).Load(processName)
	if !ok {
		return nil, false
	}
	return infoval.(*ProcessInfo), true
}

// GetOrCreateProcessInfo retrieves the ProcessInfo for a specific process within a specific pod,
// or creates and stores the provided ProcessInfo if it doesn't already exist.
// It returns the ProcessInfo and a boolean indicating whether the process information was already present.
func (d *ProcessData) GetOrCreateProcessInfo(podNamespace, podName, processName string, info *ProcessInfo) (*ProcessInfo, bool) {
	key := types.NamespacedName{Namespace: podNamespace, Name: podName}
	val, _ := d.data.LoadOrStore(key, &sync.Map{})
	infoval, loaded := val.(*sync.Map).LoadOrStore(processName, info)
	return infoval.(*ProcessInfo), loaded
}

// SetProcessInfo sets the ProcessInfo for a specific process within a specific pod.
func (d *ProcessData) SetProcessInfo(podNamespace, podName, processName string, info *ProcessInfo) {
	key := types.NamespacedName{Namespace: podNamespace, Name: podName}
	val, _ := d.data.LoadOrStore(key, &sync.Map{})
	val.(*sync.Map).Store(processName, info)
}

// UpdateProcessInfo updates a process's info using the provided update function.
// Returns false if the process doesn't exist.
func (d *ProcessData) UpdateProcessInfo(podNamespace, podName, processName string, updateFn func(*ProcessInfo)) bool {
	info, ok := d.GetProcessInfo(podNamespace, podName, processName)
	if !ok {
		return false
	}
	info.mu.Lock()
	defer info.mu.Unlock()
	updateFn(info)
	return true
}

// RemoveAllProcessInfo removes all process information for a specific pod.
// It returns a map of process names to ProcessInfo and a boolean indicating whether the pod information was found.
func (d *ProcessData) RemoveAllProcessInfo(podNamespace, podName string) (map[string]*ProcessInfo, bool) {
	key := types.NamespacedName{Namespace: podNamespace, Name: podName}
	val, ok := d.data.LoadAndDelete(key)
	if !ok {
		return nil, false
	}
	processInfoMap := make(map[string]*ProcessInfo)
	val.(*sync.Map).Range(func(key, value interface{}) bool {
		processInfoMap[key.(string)] = value.(*ProcessInfo)
		return true
	})
	return processInfoMap, true
}

// GetAllProcessInfo retrieves all process information for a specific pod.
// It returns a map of process names to ProcessInfo and a boolean indicating whether the pod information was found.
func (d *ProcessData) GetAllProcessInfo(podNamespace, podName string) (map[string]*ProcessInfo, bool) {
	key := types.NamespacedName{Namespace: podNamespace, Name: podName}
	val, ok := d.data.Load(key)
	if !ok {
		return nil, false
	}
	processInfoMap := make(map[string]*ProcessInfo)
	val.(*sync.Map).Range(func(key, value interface{}) bool {
		processInfoMap[key.(string)] = value.(*ProcessInfo)
		return true
	})
	return processInfoMap, true
}

// GetAllData retrieves all process information for all pods.
// It returns a map of NamespacedName to a map of process names to ProcessInfo.
func (d *ProcessData) GetAllData() map[types.NamespacedName]map[string]*ProcessInfo {
	processData := make(map[types.NamespacedName]map[string]*ProcessInfo)
	d.data.Range(func(key, value interface{}) bool {
		processInfoMap := make(map[string]*ProcessInfo)
		value.(*sync.Map).Range(func(key, value interface{}) bool {
			processInfoMap[key.(string)] = value.(*ProcessInfo)
			return true
		})
		processData[key.(types.NamespacedName)] = processInfoMap
		return true
	})
	return processData
}
