//go:build !linux

package projectlane

import (
	"errors"
	"time"
)

// The report writer needs descriptor-relative access: only Linux has it here. Nothing is written elsewhere.
type ReportStore struct{ Data string }

const (
	ReportsKept       = 50
	ReportWritten     = "written"
	ReportPruneFailed = "written, but older reports could not be removed"
	ReportTooLarge    = "too large"
)

func ReportKey(project string) (string, error) {
	return "", errors.New("reports are written on Linux only")
}

func (s ReportStore) Write(project string, content []byte, now time.Time) (string, error) {
	return "", errors.New("reports are written on Linux only")
}
