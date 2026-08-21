//go:build windows

package runner

import "testing"

func TestPathsOverlapTreatsDifferentWindowsVolumesAsDisjoint(t *testing.T) {
	overlaps, err := pathsOverlap(`C:\workspace`, `D:\cache\acta\staging`)
	if err != nil {
		t.Fatalf("different-volume comparison failed: %v", err)
	}
	if overlaps {
		t.Fatal("paths on different Windows volumes were reported as overlapping")
	}

	overlaps, err = pathsOverlap(`C:\workspace`, `c:\workspace\child`)
	if err != nil {
		t.Fatalf("same-volume comparison failed: %v", err)
	}
	if !overlaps {
		t.Fatal("same-volume ancestor paths were not reported as overlapping")
	}
}
