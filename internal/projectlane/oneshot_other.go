//go:build !linux

package projectlane

import "errors"

// The one-shot store needs descriptor-relative access: only Linux has it here.
type OneShotStore struct{ Home string }
type OneShotPlan struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
}
type OneShotRow struct {
	Path, Added, State string
	Dev, Inode         uint64
}

const (
	OneShotPinned   = 0
	OneShotNotPin   = 1
	OneShotReplaced = 2
)

var errOneShot = errors.New("the one-shot store is not available on this platform")

func (s OneShotStore) Check(string) int                  { return OneShotNotPin }
func (s OneShotStore) List() ([]OneShotRow, error)       { return nil, errOneShot }
func (s OneShotStore) Add([]OneShotPlan) error           { return errOneShot }
func (s OneShotStore) Remove([]string) ([]string, error) { return nil, errOneShot }
func Resolve([]string, bool) ([]OneShotPlan, error)      { return nil, errOneShot }
