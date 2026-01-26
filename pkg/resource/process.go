package resource

import "time"

// ProcessStatus represents the status of a host process.
type ProcessStatus int

const (
	// Process is pending start.
	ProcessStatusPending ProcessStatus = iota

	// Process is currently running.
	ProcessStatusRunning

	// Process has completed successfully (exit code 0).
	ProcessStatusSucceeded

	// Process has failed (non-zero exit code or error).
	ProcessStatusFailed
)

// ProcessState holds information about the current state of a process.
type ProcessState struct {
	Status     ProcessStatus
	StartedAt  time.Time
	FinishedAt time.Time
	ExitCode   int
	Error      string
}

// Process represents a native host process with its ID, name, and state.
type Process struct {
	PID   int
	Name  string
	State ProcessState
}
