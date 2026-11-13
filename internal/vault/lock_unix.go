//go:build darwin || linux

package vault

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

func lock(path string) (func(), error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open vault lock")
	}
	f := os.NewFile(uintptr(fd), path)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(fd, syscall.LOCK_UN); f.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			f.Close()
			return nil, fmt.Errorf("cannot lock vault")
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("vault is busy; retry after the other envh command finishes")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
