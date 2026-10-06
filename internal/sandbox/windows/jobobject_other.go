//go:build !windows

package windows

// JobObject stub for non-Windows platforms.
type JobObject struct{}

// CreateSandboxJob stub for non-Windows platforms.
func CreateSandboxJob() (*JobObject, error) {
	return &JobObject{}, nil
}

// AssignProcess stub for non-Windows platforms.
func (j *JobObject) AssignProcess(pid int) error {
	return nil
}

// Close stub for non-Windows platforms.
func (j *JobObject) Close() error {
	return nil
}
