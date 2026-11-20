//go:build linux

package main

import (
	"github.com/superbiche/safe/internal/projectlane"
	"github.com/superbiche/safe/internal/releases"
)

// publishCache is the lane's store of publish times under the state directory.
func publishCache(stateDir string) releases.Cache {
	return projectlane.PublishCache{StateDir: stateDir}
}
