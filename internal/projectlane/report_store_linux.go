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
//   - the data directory is opened by the path it is given (as the other stores open their root); the chain below it (the lane's
//     directory, the reports directory, the project's directory) is opened one name at a time through held descriptors, never following a
//     link, each owned by the user and closed to group and others (the reports directory and the project's directory are created 0700
//     here: the gate never makes or names them);
//   - the file is created below the held project directory with its final mode (0600), written, synced, and renamed into place without
//     replacing anything; a name is time, process and a random part, so two commands of one second cannot meet;
//   - retention: the newest ReportsKept of the project stay. Pruning removes only regular files of the report name pattern, by name below
//     the held directory, never through a link, and never anything outside the project's own directory; one that cannot be removed is
//     said by the result, nothing else.
//
// The project's key (the directory's name) is the digest of the project's physical path. It is not a member of any document.

// ReportsKept is how many reports of one project are kept.
const ReportsKept = 50

// The name of a report: the UTC time to the microsecond (so that the names sort in the order the documents were written, and retention
// removes the oldest), the process and a random part.
var reportName = regexp.MustCompile(`\A[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9]+-[0-9a-f]{8}\.json\z`)

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
	now = afterNewest(dir, now)
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%d-%s.json", now.UTC().Format(reportStamp), os.Getpid(), hex.EncodeToString(random[:]))
	staged := ".staged-" + name
	if _, err := dir.createExclusiveMode(staged, content, 0o600); err != nil {
		return "", err
	}
	if err := moveNoReplace(dir, staged, dir, name); err != nil {
		_ = dir.remove(staged)
		return "", err
	}
	// the document is in place: a directory sync that fails now does not make it "not written"
	_ = dirSync(dir)
	if err := pruneReports(dir, name); err != nil {
		return ReportPruneFailed, nil
	}
	return ReportWritten, nil
}

const reportStamp = "20060102T150405.000000Z"

// afterNewest returns a time later than the newest report of the project, so that the names sort in the order of the writes whatever the
// clock says (two writes in one microsecond, a clock that went back): retention removes the oldest.
func afterNewest(dir *dirHandle, now time.Time) time.Time {
	names, err := dir.names()
	if err != nil {
		return now
	}
	now = now.UTC().Truncate(time.Microsecond)
	for _, name := range names {
		if !reportName.MatchString(name) {
			continue
		}
		if at, err := time.Parse(reportStamp, name[:len(reportStamp)]); err == nil && !now.After(at) {
			now = at.Add(time.Microsecond)
		}
	}
	return now
}

// pruneReports removes the oldest reports past the bound, never the one named own: regular files of the pattern only.
func pruneReports(dir *dirHandle, own string) error {
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
		if err != nil || !info.Mode().IsRegular() || !oneShotOwned(info) {
			continue
		}
		mine = append(mine, name)
	}
	sort.Strings(mine)
	var failed error
	// the oldest past the bound go, and never the document this writer has just put in place (another writer, stamped later, may have
	// finished first: the overlap must not cost a writer its own file)
	excess := len(mine) - ReportsKept
	for _, name := range mine {
		if excess <= 0 {
			break
		}
		if name == own {
			continue
		}
		excess--
		if err := dir.remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = err
		}
	}
	return failed
}
