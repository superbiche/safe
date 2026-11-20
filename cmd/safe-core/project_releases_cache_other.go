//go:build !linux

package main

import "github.com/superbiche/safe/internal/releases"

// publishCache: the store's checks are written for Linux; elsewhere nothing is cached, every reading asks the registry.
func publishCache(stateDir string) releases.Cache { return nil }
