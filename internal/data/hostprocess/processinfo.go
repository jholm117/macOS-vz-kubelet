package hostprocess

import (
	"io"
	"os/exec"
	"sync"
	"time"
)

// ProcessInfo holds information about a host process managed by the kubelet.
type ProcessInfo struct {
	Name       string         // Process name (container name from pod spec)
	Command    []string       // Command to run
	Args       []string       // Arguments to pass
	WorkingDir string         // Working directory
	PID        int            // Process ID once started
	Cmd        *exec.Cmd      // The exec.Cmd for managing the process
	StartedAt  time.Time      // When the process started
	FinishedAt time.Time      // When the process finished (if applicable)
	ExitCode   int            // Exit code (valid only after process exits)
	Error      error          // Error encountered during process lifecycle
	Stdout     io.ReadCloser  // Stdout pipe for logs
	Stderr     io.ReadCloser  // Stderr pipe for logs
	mu         sync.Mutex     // Protects mutable fields
}

// WithPID sets the PID of the ProcessInfo and returns the updated ProcessInfo.
func (p ProcessInfo) WithPID(pid int) ProcessInfo {
	p.PID = pid
	return p
}

// WithError sets the Error of the ProcessInfo and returns the updated ProcessInfo.
func (p ProcessInfo) WithError(err error) ProcessInfo {
	p.Error = err
	return p
}

// WithStartedAt sets the StartedAt time of the ProcessInfo and returns the updated ProcessInfo.
func (p ProcessInfo) WithStartedAt(t time.Time) ProcessInfo {
	p.StartedAt = t
	return p
}

// WithFinishedAt sets the FinishedAt time and exit code of the ProcessInfo.
func (p ProcessInfo) WithFinishedAt(t time.Time, exitCode int) ProcessInfo {
	p.FinishedAt = t
	p.ExitCode = exitCode
	return p
}

// IsRunning returns true if the process is currently running.
func (p *ProcessInfo) IsRunning() bool {
	if p.Cmd == nil || p.Cmd.Process == nil {
		return false
	}
	// Check if process has exited
	if p.Cmd.ProcessState != nil {
		return false
	}
	return true
}
