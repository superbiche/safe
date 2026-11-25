//go:build !linux

package projectlane

import "errors"

// The one-shot store needs descriptor-relative access: only Linux has it here. Nothing is pinned elsewhere.
type OneShotStore struct{ Home string }
type OneShotEntry struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
	Added string `json:"added"`
}
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

var (
	errOneShot             = errors.New("the one-shot store is not available on this platform")
	ErrNotRecorded         = errors.New("the change was NOT recorded")
	ErrDurabilityUncertain = errors.New("durability uncertain")
)

func (s OneShotStore) CheckHere() int                               { return OneShotNotPin }
func (s OneShotStore) VerifyAnswer(prefix, root []byte) int         { return OneShotNotPin }
func (s OneShotStore) List() ([]OneShotRow, error)                  { return nil, errOneShot }
func (s OneShotStore) Add([]OneShotPlan) error                      { return errOneShot }
func (s OneShotStore) Remove([]string) ([]string, error)            { return nil, errOneShot }
func (s OneShotStore) ShowRemoval([]string) ([]OneShotEntry, error) { return nil, errOneShot }
func (s OneShotStore) RemoveEntries([]OneShotEntry) error           { return errOneShot }
func Resolve([]string, bool) ([]OneShotPlan, error)                 { return nil, errOneShot }
