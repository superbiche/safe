//go:build !linux

package projectlane

import "time"

// The store's checks are written for Linux; elsewhere nothing is cached and every record is fetched.
type AdvisoryCache struct{ StateDir string }

func (AdvisoryCache) Get(string, []AdvisoryKey, time.Time) []AdvisoryReading { return nil }
func (AdvisoryCache) Put(string, []AdvisoryReading, time.Time)               {}
