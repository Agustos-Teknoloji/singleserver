package singleserver

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// The registry lock coordinates every process that uses the local registry:
// the daemon's webhook deploys and `singleserver deploy` run from the CLI.
// Deploys hold it shared while Kamal builds and pushes; registry retention
// holds it exclusively while it deletes manifests, garbage-collects blobs and
// restarts the registry. It is an flock on a file in the state directory, so
// it works across processes and between goroutines (each acquire opens its
// own file description), and the kernel drops it if a process dies.

func registryLockPath() string {
	return filepath.Join(envDefault("SINGLESERVER_STATE_DIR", "/etc/singleserver"), "registry.lock")
}

// acquireRegistryLock blocks until the lock is held and returns its release.
func acquireRegistryLock(exclusive bool) (func(), error) {
	path := registryLockPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("registry lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("registry lock: %w", err)
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	for {
		err = syscall.Flock(int(file.Fd()), how)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("registry lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
	}, nil
}
