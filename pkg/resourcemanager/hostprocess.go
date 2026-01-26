package resourcemanager

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	hostprocessdata "github.com/agoda-com/macOS-vz-kubelet/internal/data/hostprocess"
	"github.com/agoda-com/macOS-vz-kubelet/pkg/resource"

	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	"github.com/virtual-kubelet/virtual-kubelet/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	stats "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
)

const (
	// HostProcessNamePrefix is the prefix for host process names.
	HostProcessNamePrefix = "macos-vz-hp"

	// LogDir is where process logs are stored.
	HostProcessLogDir = "/var/log/macos-vz-kubelet/hostprocess"
)

// HostProcess manages native host processes for pods.
type HostProcess struct {
	data   hostprocessdata.ProcessData
	logDir string
	mu     sync.RWMutex
}

// NewHostProcessClient creates a new HostProcessClient.
func NewHostProcessClient(ctx context.Context) (*HostProcess, error) {
	_, span := trace.StartSpan(ctx, "hostProcess.NewHostProcessClient")
	defer span.End()

	logDir := HostProcessLogDir
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", logDir, err)
	}

	return &HostProcess{
		logDir: logDir,
	}, nil
}

// CreateProcess creates and starts a host process.
func (h *HostProcess) CreateProcess(ctx context.Context, params HostProcessParams) (err error) {
	ctx, span := trace.StartSpan(ctx, "HostProcess.CreateProcess")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	processKey := fmt.Sprintf("%s/%s/%s", params.PodNamespace, params.PodName, params.Name)
	log.G(ctx).Infof("Creating host process: %s", processKey)

	// Check if process already exists
	if existing, exists := h.data.GetProcessInfo(params.PodNamespace, params.PodName, params.Name); exists {
		if existing.IsRunning() {
			log.G(ctx).Warnf("Process %s already running with PID %d", processKey, existing.PID)
			return nil
		}
		// Process exists but not running, clean it up
		log.G(ctx).Infof("Cleaning up stopped process %s", processKey)
	}

	// Build the command
	if len(params.Command) == 0 {
		return fmt.Errorf("command is required for host process")
	}

	cmdPath := params.Command[0]
	cmdArgs := append(params.Command[1:], params.Args...)

	cmd := exec.CommandContext(ctx, cmdPath, cmdArgs...)

	// Set working directory
	if params.WorkingDir != "" {
		cmd.Dir = params.WorkingDir
	}

	// Set environment variables
	cmd.Env = os.Environ() // Start with current environment
	for _, env := range params.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", env.Name, env.Value))
	}

	// Set up log files for stdout/stderr
	logFileBase := filepath.Join(h.logDir, fmt.Sprintf("%s_%s_%s", params.PodNamespace, params.PodName, params.Name))
	stdoutFile, err := os.Create(logFileBase + ".stdout.log")
	if err != nil {
		return fmt.Errorf("failed to create stdout log file: %w", err)
	}
	stderrFile, err := os.Create(logFileBase + ".stderr.log")
	if err != nil {
		stdoutFile.Close()
		return fmt.Errorf("failed to create stderr log file: %w", err)
	}

	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile

	// Start the process
	if err := cmd.Start(); err != nil {
		stdoutFile.Close()
		stderrFile.Close()
		return fmt.Errorf("failed to start process: %w", err)
	}

	// Store process info
	info := &hostprocessdata.ProcessInfo{
		Name:       params.Name,
		Command:    params.Command,
		Args:       params.Args,
		WorkingDir: params.WorkingDir,
		PID:        cmd.Process.Pid,
		Cmd:        cmd,
		StartedAt:  time.Now(),
	}

	h.data.SetProcessInfo(params.PodNamespace, params.PodName, params.Name, info)

	log.G(ctx).Infof("Started host process %s with PID %d", processKey, cmd.Process.Pid)

	// Monitor process in background
	go h.monitorProcess(params.PodNamespace, params.PodName, params.Name, cmd, stdoutFile, stderrFile)

	return nil
}

// monitorProcess waits for a process to exit and updates its state.
func (h *HostProcess) monitorProcess(podNs, podName, processName string, cmd *exec.Cmd, stdout, stderr *os.File) {
	defer stdout.Close()
	defer stderr.Close()

	err := cmd.Wait()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	h.data.UpdateProcessInfo(podNs, podName, processName, func(info *hostprocessdata.ProcessInfo) {
		info.FinishedAt = time.Now()
		info.ExitCode = exitCode
		if err != nil {
			info.Error = err
		}
	})

	log.L.Infof("Host process %s/%s/%s exited with code %d", podNs, podName, processName, exitCode)
}

// RemoveProcesses stops and removes all processes for a pod.
func (h *HostProcess) RemoveProcesses(ctx context.Context, podNs, podName string, gracePeriod int64) (err error) {
	ctx, span := trace.StartSpan(ctx, "HostProcess.RemoveProcesses")
	defer func() {
		span.SetStatus(err)
		span.End()
	}()

	processes, ok := h.data.RemoveAllProcessInfo(podNs, podName)
	if !ok {
		log.G(ctx).Debugf("No processes found for pod %s/%s", podNs, podName)
		return nil
	}

	var errs []error
	for name, info := range processes {
		if info.Cmd != nil && info.Cmd.Process != nil && info.IsRunning() {
			log.G(ctx).Infof("Stopping process %s (PID %d) for pod %s/%s", name, info.PID, podNs, podName)

			// Try graceful termination first
			if err := info.Cmd.Process.Signal(syscall.SIGTERM); err != nil {
				log.G(ctx).Warnf("Failed to send SIGTERM to process %d: %v", info.PID, err)
			}

			// Wait for grace period, then force kill
			done := make(chan struct{})
			go func() {
				info.Cmd.Wait()
				close(done)
			}()

			select {
			case <-done:
				log.G(ctx).Infof("Process %s terminated gracefully", name)
			case <-time.After(time.Duration(gracePeriod) * time.Second):
				log.G(ctx).Warnf("Process %s did not terminate within grace period, sending SIGKILL", name)
				if err := info.Cmd.Process.Kill(); err != nil {
					errs = append(errs, fmt.Errorf("failed to kill process %s: %w", name, err))
				}
			}
		}
	}

	// Clean up log files
	logPattern := filepath.Join(h.logDir, fmt.Sprintf("%s_%s_*", podNs, podName))
	files, _ := filepath.Glob(logPattern)
	for _, f := range files {
		os.Remove(f)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors removing processes: %v", errs)
	}
	return nil
}

// GetProcesses returns the list of processes for a pod.
func (h *HostProcess) GetProcesses(ctx context.Context, podNs, podName string) ([]resource.Process, error) {
	_, span := trace.StartSpan(ctx, "HostProcess.GetProcesses")
	defer span.End()

	infoMap, ok := h.data.GetAllProcessInfo(podNs, podName)
	if !ok {
		return nil, nil
	}

	processes := make([]resource.Process, 0, len(infoMap))
	for _, info := range infoMap {
		processes = append(processes, h.infoToProcess(info))
	}
	return processes, nil
}

// GetProcessesListResult returns all processes for all pods.
func (h *HostProcess) GetProcessesListResult(ctx context.Context) (map[k8stypes.NamespacedName][]resource.Process, error) {
	_, span := trace.StartSpan(ctx, "HostProcess.GetProcessesListResult")
	defer span.End()

	allData := h.data.GetAllData()
	result := make(map[k8stypes.NamespacedName][]resource.Process, len(allData))

	for nsName, infoMap := range allData {
		processes := make([]resource.Process, 0, len(infoMap))
		for _, info := range infoMap {
			processes = append(processes, h.infoToProcess(info))
		}
		result[nsName] = processes
	}
	return result, nil
}

// infoToProcess converts ProcessInfo to resource.Process.
func (h *HostProcess) infoToProcess(info *hostprocessdata.ProcessInfo) resource.Process {
	status := resource.ProcessStatusPending
	if info.PID > 0 {
		if info.IsRunning() {
			status = resource.ProcessStatusRunning
		} else if info.ExitCode == 0 {
			status = resource.ProcessStatusSucceeded
		} else {
			status = resource.ProcessStatusFailed
		}
	}

	errStr := ""
	if info.Error != nil {
		errStr = info.Error.Error()
	}

	return resource.Process{
		PID:  info.PID,
		Name: info.Name,
		State: resource.ProcessState{
			Status:     status,
			StartedAt:  info.StartedAt,
			FinishedAt: info.FinishedAt,
			ExitCode:   info.ExitCode,
			Error:      errStr,
		},
	}
}

// GetProcessLogs returns the logs for a specific process.
func (h *HostProcess) GetProcessLogs(ctx context.Context, namespace, podName, processName string, opts api.ContainerLogOpts) (io.ReadCloser, error) {
	_, span := trace.StartSpan(ctx, "HostProcess.GetProcessLogs")
	defer span.End()

	// Read from log files
	logFile := filepath.Join(h.logDir, fmt.Sprintf("%s_%s_%s.stdout.log", namespace, podName, processName))

	f, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty reader if no logs yet
			return io.NopCloser(bufio.NewReader(nil)), nil
		}
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Handle tail option
	if opts.Tail > 0 {
		return h.tailLogFile(f, opts.Tail)
	}

	return f, nil
}

// tailLogFile returns the last n lines of a log file.
func (h *HostProcess) tailLogFile(f *os.File, n int) (io.ReadCloser, error) {
	// Simple implementation: read all lines and return last n
	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	f.Close()

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	start := 0
	if len(lines) > n {
		start = len(lines) - n
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for _, line := range lines[start:] {
			fmt.Fprintln(pw, line)
		}
	}()

	return pr, nil
}

// ExecInProcess executes a command in the context of a process.
// For host processes, this is limited since we can't "exec into" a native process.
// We run the command with similar environment instead.
func (h *HostProcess) ExecInProcess(ctx context.Context, namespace, podName, processName string, cmd []string, attach api.AttachIO) error {
	_, span := trace.StartSpan(ctx, "HostProcess.ExecInProcess")
	defer span.End()

	info, ok := h.data.GetProcessInfo(namespace, podName, processName)
	if !ok {
		return fmt.Errorf("process %s not found in pod %s/%s", processName, namespace, podName)
	}

	if len(cmd) == 0 {
		return fmt.Errorf("command is required")
	}

	execCmd := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	if info.WorkingDir != "" {
		execCmd.Dir = info.WorkingDir
	}

	if attach.Stdin() != nil {
		execCmd.Stdin = attach.Stdin()
	}
	if attach.Stdout() != nil {
		execCmd.Stdout = attach.Stdout()
	}
	if attach.Stderr() != nil {
		execCmd.Stderr = attach.Stderr()
	}

	return execCmd.Run()
}

// IsProcessPresent checks if a process exists for a pod.
func (h *HostProcess) IsProcessPresent(ctx context.Context, podNs, podName, processName string) bool {
	_, span := trace.StartSpan(ctx, "HostProcess.IsProcessPresent")
	defer span.End()

	_, ok := h.data.GetProcessInfo(podNs, podName, processName)
	return ok
}

// GetProcessStats returns resource stats for a process.
func (h *HostProcess) GetProcessStats(ctx context.Context, podNs, podName, processName string) (stats.ContainerStats, error) {
	_, span := trace.StartSpan(ctx, "HostProcess.GetProcessStats")
	defer span.End()

	info, ok := h.data.GetProcessInfo(podNs, podName, processName)
	if !ok {
		return stats.ContainerStats{}, fmt.Errorf("process %s not found", processName)
	}

	now := metav1.Now()

	// Basic stats - for more detailed stats we'd need to query the OS
	return stats.ContainerStats{
		Name:      processName,
		StartTime: metav1.NewTime(info.StartedAt),
		CPU:       &stats.CPUStats{Time: now},
		Memory:    &stats.MemoryStats{Time: now},
	}, nil
}
