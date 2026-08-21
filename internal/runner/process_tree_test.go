package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessTreeKillsDescendants(t *testing.T) {
	role := os.Getenv("ACTA_PROCESS_TREE_HELPER")
	marker := os.Getenv("ACTA_PROCESS_TREE_MARKER")
	ready := os.Getenv("ACTA_PROCESS_TREE_READY")
	switch role {
	case "child":
		time.Sleep(400 * time.Millisecond)
		_ = os.WriteFile(marker, []byte("survived"), 0o600)
		os.Exit(0)
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestProcessTreeKillsDescendants$")
		child.Env = append(os.Environ(), "ACTA_PROCESS_TREE_HELPER=child")
		if err := child.Start(); err != nil {
			os.Exit(20)
		}
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
			os.Exit(21)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}

	dir := t.TempDir()
	marker = filepath.Join(dir, "grandchild-survived")
	ready = filepath.Join(dir, "grandchild-ready")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessTreeKillsDescendants$")
	cmd.Env = append(os.Environ(),
		"ACTA_PROCESS_TREE_HELPER=parent",
		"ACTA_PROCESS_TREE_MARKER="+marker,
		"ACTA_PROCESS_TREE_READY="+ready,
	)
	done := make(chan error, 1)
	go func() { done <- runProcessTree(ctx, cmd) }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("helper grandchild did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("canceled process tree returned no error")
	}
	time.Sleep(600 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("grandchild survived process-tree cancellation: %v", err)
	}
}
