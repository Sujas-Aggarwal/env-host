//go:build windows

package vault

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"time"
)

func lock(path string) (func(), error) {
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("unsafe lock file")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	o := new(windows.Overlapped)
	deadline := time.Now().Add(5 * time.Second)
	for {
		e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, o)
		if e == nil {
			return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, o); f.Close() }, nil
		}
		if e != windows.ERROR_LOCK_VIOLATION || time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("vault is busy or cannot be locked")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func syncDir(string) error { return nil }
