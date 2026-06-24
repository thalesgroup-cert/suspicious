// Package source provides IMAP ingestion and UID deduplication for the
// email-feeder. The Dedup type is a bounded LRU that prevents the same
// (mailbox, UID) pair from being processed more than once within its window.
// The Source type connects to IMAP mailboxes, discovers new messages, and
// emits them as RawEmail values on a channel.
package source

import (
	"container/list"
	"fmt"
	"sync"
)

// Dedup is a bounded LRU seen-set keyed on (mailbox, uid) pairs.
// Once the set reaches its maximum capacity the least-recently-marked entry
// is evicted, allowing that UID to be reprocessed should it be redelivered
// after the eviction window.
type Dedup struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	set map[string]*list.Element
}

// NewDedup creates a Dedup that retains at most max entries.
func NewDedup(max int) *Dedup {
	return &Dedup{max: max, ll: list.New(), set: map[string]*list.Element{}}
}

func key(mailbox string, uid uint32) string { return fmt.Sprintf("%s/%d", mailbox, uid) }

// Seen reports whether (mailbox, uid) has been marked.
func (d *Dedup) Seen(mailbox string, uid uint32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.set[key(mailbox, uid)]
	return ok
}

// Mark records (mailbox, uid) as seen, evicting the oldest entry if the
// capacity limit has been reached.
func (d *Dedup) Mark(mailbox string, uid uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := key(mailbox, uid)
	if _, ok := d.set[k]; ok {
		return
	}
	d.set[k] = d.ll.PushFront(k)
	for d.ll.Len() > d.max {
		back := d.ll.Back()
		d.ll.Remove(back)
		delete(d.set, back.Value.(string))
	}
}
