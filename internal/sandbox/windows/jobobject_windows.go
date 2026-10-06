//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// JobObject manages a Windows Job Object handle for process lifecycle and security limits.
type JobObject struct {
	handle windows.Handle
}

// CreateSandboxJob creates and configures a Windows Job Object with strict termination and sandbox limits.
func CreateSandboxJob() (*JobObject, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Windows Job Object: %w", err)
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
				windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
		},
	}

	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("failed to set Job Object limits: %w", err)
	}

	return &JobObject{handle: job}, nil
}

// AssignProcess assigns a process ID to this Job Object.
func (j *JobObject) AssignProcess(pid int) error {
	if j == nil || j.handle == 0 {
		return nil
	}
	hProcess, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("failed to open process %d for Job Object assignment: %w", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	if err := windows.AssignProcessToJobObject(j.handle, hProcess); err != nil {
		return fmt.Errorf("failed to assign process %d to Job Object: %w", pid, err)
	}
	return nil
}

// Close closes the Job Object handle.
func (j *JobObject) Close() error {
	if j == nil || j.handle == 0 {
		return nil
	}
	err := windows.CloseHandle(j.handle)
	j.handle = 0
	return err
}
