package util

import (
	"container/list"
	"hash/maphash"
	"reflect"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-libs/mapstr"
)

const metadataTreeBudget = 2 << 20

type metadataTreeEntry struct {
	hash       uint64
	fields     mapstr.M
	bytes      int
	lastAccess time.Time
}

type metadataTreeInterner struct {
	sync.Mutex
	seed    maphash.Seed
	entries map[uint64][]*list.Element
	recent  list.List
	bytes   int
}

func (pool *metadataTreeInterner) share(meta mapstr.M, now time.Time) mapstr.M {
	pool.Lock()
	defer pool.Unlock()
	if pool.entries == nil {
		pool.entries = make(map[uint64][]*list.Element)
		pool.seed = maphash.MakeSeed()
	}
	for oldest := pool.recent.Back(); oldest != nil; oldest = pool.recent.Back() {
		if now.Sub(oldest.Value.(*metadataTreeEntry).lastAccess) < metadataLabelIdleTTL {
			break
		}
		pool.remove(oldest)
	}
	result, _, _ := pool.tree(meta, now, 0)
	return result
}

func (pool *metadataTreeInterner) tree(source mapstr.M, now time.Time, depth int) (mapstr.M, uint64, bool) {
	if source == nil || depth > 16 {
		return source, 0, false
	}
	result := source
	copied, supported := false, true
	weight := 128 + len(source)*64
	var hash uint64
	for key, value := range source {
		var childHash uint64
		switch child := value.(type) {
		case string:
			childHash = maphash.String(pool.seed, child)
			weight += len(child)
		case mapstr.M:
			shared, fingerprint, valid := pool.tree(child, now, depth+1)
			childHash, supported = fingerprint, supported && valid
			if !copied {
				result = make(mapstr.M, len(source))
				for field, original := range source {
					result[field] = original
				}
				copied = true
			}
			result[key] = shared
		default:
			supported = false
		}
		keyHash := maphash.String(pool.seed, key)
		hash += keyHash ^ (childHash + 0x9e3779b97f4a7c15 + (keyHash << 6) + (keyHash >> 2))
		weight += len(key)
	}
	if !supported || depth == 0 || weight > metadataTreeBudget/4 {
		return result, hash, supported
	}
	for _, candidate := range pool.entries[hash] {
		entry := candidate.Value.(*metadataTreeEntry)
		if reflect.DeepEqual(entry.fields, result) {
			entry.lastAccess = now
			pool.recent.MoveToFront(candidate)
			return entry.fields, hash, true
		}
	}
	for pool.recent.Len() >= 4096 || pool.bytes+weight > metadataTreeBudget {
		pool.remove(pool.recent.Back())
	}
	entry := &metadataTreeEntry{hash: hash, fields: result, bytes: weight, lastAccess: now}
	pool.entries[hash] = append(pool.entries[hash], pool.recent.PushFront(entry))
	pool.bytes += weight
	return result, hash, true
}

func (pool *metadataTreeInterner) remove(element *list.Element) {
	entry := element.Value.(*metadataTreeEntry)
	chain := pool.entries[entry.hash]
	for index, candidate := range chain {
		if candidate == element {
			chain = append(chain[:index], chain[index+1:]...)
			break
		}
	}
	if len(chain) == 0 {
		delete(pool.entries, entry.hash)
	} else {
		pool.entries[entry.hash] = chain
	}
	pool.bytes -= entry.bytes
	pool.recent.Remove(element)
}
