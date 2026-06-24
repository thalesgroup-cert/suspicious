package source

import "testing"

func TestDedupMarkAndSeen(t *testing.T) {
	d := NewDedup(2)
	if d.Seen("a", 1) {
		t.Fatal("unseen uid reported seen")
	}
	d.Mark("a", 1)
	if !d.Seen("a", 1) {
		t.Fatal("marked uid not seen")
	}
	// eviction past capacity
	d.Mark("a", 2)
	d.Mark("a", 3)
	if d.Seen("a", 1) {
		t.Fatal("uid 1 should have been evicted")
	}
}
