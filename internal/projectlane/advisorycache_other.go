//go:build !linux

package projectlane

import "time"

// The store's checks are written for Linux; elsewhere nothing is cached and every record is fetched.
const (
	AdvisoryCacheSchema = 1
	AdvisoryMaxAge      = 24 * time.Hour
	AdvisoryCap         = 10000
)

type AdvisoryKey struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	Package  string `json:"package"`
}

type AdvisoryReading struct {
	AdvisoryKey
	Severity  string `json:"severity"`
	Withdrawn bool   `json:"withdrawn"`
	Fetched   int64  `json:"fetched"`
}

type AdvisoryCache struct{ StateDir string }

func (AdvisoryCache) Get(string, []AdvisoryKey, time.Time) []AdvisoryReading { return nil }
func (AdvisoryCache) Put(string, []AdvisoryReading, time.Time)               {}
