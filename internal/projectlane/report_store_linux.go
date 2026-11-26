//go:build linux

package projectlane

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The reports of a project (ticket 1639): ONE writer. A report is a file of its own in a directory per project, below the lane's
// reports directory, below safe's data directory:
//
//   - the chain of directories is opened one name at a time through held descriptors, never following a link, each owned by the user
//     and closed to group and others (the reports directory and the project's directory are created 0700);
//   - the file is created below the held project directory with its final mode (0600), written, synced, and renamed into place without
//     replacing anything; a name is time, process and a random part, so two commands of one second cannot meet;
//   - retention: the newest ReportsKept of the project stay. Pruning removes only regular files of the report name pattern, by name below
//     the held directory, never through a link, and never anything outside the project's own directory; one that cannot be removed is
//     said by the result, nothing else.
//
// The project's key (the directory's name) is the digest of the project's physical path. It is not a member of any document.

// ReportsKept is how many reports of one project are kept.
const ReportsKept = 50

var reportName = regexp.MustCompile(`\A[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9a-f]{8}\.json\z`)

// ReportStore is the lane's data directory (<data>/project-lane lives below it).
type ReportStore struct{ Data string }

// Report-write results.
const (
	ReportWritten     = "written"
	ReportPruneFailed = "written, but older reports could not be removed"
	ReportTooLarge    = "too large"
)

// ReportKey is the name of a project's directory.
func ReportKey(project string) (string, error) {
	if !strings.HasPrefix(project, "/") || strings.ContainsRune(project, 0) {
		return "", errors.New("the project is not an absolute path")
	}
	sum := sha256.Sum256([]byte(project))
	return hex.EncodeToString(sum[:]), nil
}

func (s ReportStore) openProjectDir(key string) (*dirHandle, error) {
	if !strings.HasPrefix(s.Data, "/") {
		return nil, errors.New("the data directory is not absolute")
	}
	current, err := openDirPath(s.Data)
	if err != nil {
		return nil, err
	}
	if err := oneShotCheckDir(current, "the data directory"); err != nil {
		current.Close()
		return nil, err
	}
	for _, name := range []string{"project-lane", "reports", key} {
		next, err := current.openDirNoFollow(name)
		if err != nil && errors.Is(err, os.ErrNotExist) && name != "project-lane" {
			if merr := current.mkdir(name, 0o700); merr != nil && !errors.Is(merr, os.ErrExist) {
				current.Close()
				return nil, merr
			}
			next, err = current.openDirNoFollow(name)
		}
		current.Close()
		if err != nil {
			return nil, err
		}
		if err := oneShotCheckDir(next, "the directory "+name); err != nil {
			next.Close()
			return nil, err
		}
		if name != "project-lane" {
			info, err := next.f.Stat()
			if err != nil || info.Mode().Perm()&0o077 != 0 {
				next.Close()
				return nil, fmt.Errorf("the directory %s is open to group or others", name)
			}
		}
		current = next
	}
	return current, nil
}

// Write stores one document for a project. The result is one of the Report* constants; an error means nothing was written.
func (s ReportStore) Write(project string, content []byte, now time.Time) (string, error) {
	if len(content) > MaxReportBytes {
		return ReportTooLarge, nil
	}
	key, err := ReportKey(project)
	if err != nil {
		return "", err
	}
	dir, err := s.openProjectDir(key)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%d-%s.json", now.UTC().Format("20060102T150405Z"), os.Getpid(), hex.EncodeToString(random[:]))
	staged := ".staged-" + name
	if _, err := dir.createExclusiveMode(staged, content, 0o600); err != nil {
		return "", err
	}
	if err := moveNoReplace(dir, staged, dir, name); err != nil {
		_ = dir.remove(staged)
		return "", err
	}
	if err := dirSync(dir); err != nil {
		return "", err
	}
	if err := pruneReports(dir); err != nil {
		return ReportPruneFailed, nil
	}
	return ReportWritten, nil
}

// pruneReports removes the oldest reports past the bound: regular files of the pattern only.
func pruneReports(dir *dirHandle) error {
	names, err := dir.names()
	if err != nil {
		return err
	}
	var mine []string
	for _, name := range names {
		if !reportName.MatchString(name) {
			continue
		}
		info, err := dir.lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		mine = append(mine, name)
	}
	sort.Strings(mine)
	var failed error
	for i := 0; i < len(mine)-ReportsKept; i++ {
		if err := dir.remove(mine[i]); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = err
		}
	}
	return failed
}
