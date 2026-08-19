//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProcessGroupContractExcludesDetachedDescendant(t *testing.T) {
	role := os.Getenv("ACTA_DETACHED_TREE_HELPER")
	marker := os.Getenv("ACTA_DETACHED_TREE_MARKER")
	ready := os.Getenv("ACTA_DETACHED_TREE_READY")
	pidPath := os.Getenv("ACTA_DETACHED_TREE_PID")
	switch role {
	case "child":
		time.Sleep(800 * time.Millisecond)
		_ = os.WriteFile(marker, []byte("survived"), 0o600)
		os.Exit(0)
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestProcessGroupContractExcludesDetachedDescendant$")
		child.Env = append(os.Environ(), "ACTA_DETACHED_TREE_HELPER=child")
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := child.Start(); err != nil {
			os.Exit(20)
		}
		if err := os.WriteFile(pidPath, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			_ = child.Process.Kill()
			os.Exit(21)
		}
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
			_ = child.Process.Kill()
			os.Exit(22)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}

	dir := t.TempDir()
	marker = filepath.Join(dir, "detached-survived")
	ready = filepath.Join(dir, "detached-ready")
	pidPath = filepath.Join(dir, "detached-pid")
	t.Cleanup(func() {
		payload, err := os.ReadFile(pidPath)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(payload)))
		if err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessGroupContractExcludesDetachedDescendant$")
	cmd.Env = append(os.Environ(),
		"ACTA_DETACHED_TREE_HELPER=parent",
		"ACTA_DETACHED_TREE_MARKER="+marker,
		"ACTA_DETACHED_TREE_READY="+ready,
		"ACTA_DETACHED_TREE_PID="+pidPath,
	)
	done := make(chan error, 1)
	go func() { done <- runProcessTree(ctx, cmd) }()
	waitForFile(t, ready, 3*time.Second, func() {
		cancel()
		<-done
	})
	cancel()
	if err := <-done; err == nil {
		t.Fatal("canceled process tree returned no error")
	}
	time.Sleep(time.Second)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("detached descendant should be explicitly outside the POSIX process-group contract: %v", err)
	}
}

func waitForFile(t *testing.T, path string, timeout time.Duration, cleanup func()) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			cleanup()
			t.Fatalf("timed out waiting for %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
