//go:build !linux

package main

import "os"

// isTerminal on a platform without the store (the standing decision's store is Linux-only): no terminal is recognised, so the
// writer refuses (102) and nothing can be pinned, which is the store's own fallback there.
func isTerminal(*os.File) bool { return false }
