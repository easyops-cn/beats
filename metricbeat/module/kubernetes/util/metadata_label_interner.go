package util

import (
	"container/list"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	metadataLabelMaxEntries = 2048
	metadataLabelKeyBudget  = 1 << 20
	metadataLabelMaxKeySize = 64 << 10
	metadataLabelIdleTTL    = 10 * time.Minute
)

type metadataLabelInterner struct {
	sync.Mutex
	entries  map[string]*list.Element
	recent   list.List
	keyBytes int
}

type metadataLabelEntry struct {
	key        string
	fields     mapstr.M
	lastAccess time.Time
}

func (repo *MetricsRepo) internMetadataLabels(meta mapstr.M) mapstr.M {
	repo.metadataLabels.share(meta, time.Now())
	return repo.metadataTrees.share(meta, time.Now())
}

func (interner *metadataLabelInterner) share(meta mapstr.M, now time.Time) {
	for key, child := range meta {
		fields, ok := child.(mapstr.M)
		if !ok {
			continue
		}
		if key == "labels" || key == "annotations" || strings.HasSuffix(key, "_labels") || strings.HasSuffix(key, "_annotations") {
			meta[key] = interner.intern(fields, now)
		} else {
			interner.share(fields, now)
		}
	}
}

func (interner *metadataLabelInterner) intern(fields mapstr.M, now time.Time) mapstr.M {
	if len(fields) == 0 {
		return fields
	}
	var scratch [4096]byte
	encoded, supported := appendMetadataLabelKey(scratch[:0], fields, 0)
	if !supported {
		return fields
	}
	interner.Lock()
	defer interner.Unlock()
	for oldest := interner.recent.Back(); oldest != nil; oldest = interner.recent.Back() {
		if now.Sub(oldest.Value.(*metadataLabelEntry).lastAccess) < metadataLabelIdleTTL {
			break
		}
		interner.remove(oldest)
	}
	if entry := interner.entries[string(encoded)]; entry != nil {
		stored := entry.Value.(*metadataLabelEntry)
		stored.lastAccess = now
		interner.recent.MoveToFront(entry)
		return stored.fields
	}
	key := string(encoded)
	for len(interner.entries) >= metadataLabelMaxEntries || interner.keyBytes+len(key) > metadataLabelKeyBudget {
		interner.remove(interner.recent.Back())
	}
	if interner.entries == nil {
		interner.entries = make(map[string]*list.Element)
	}
	interner.entries[key] = interner.recent.PushFront(&metadataLabelEntry{key: key, fields: fields, lastAccess: now})
	interner.keyBytes += len(key)
	return fields
}

func (interner *metadataLabelInterner) remove(entry *list.Element) {
	stored := entry.Value.(*metadataLabelEntry)
	delete(interner.entries, stored.key)
	interner.keyBytes -= len(stored.key)
	interner.recent.Remove(entry)
}

func appendMetadataLabelKey(buffer []byte, value interface{}, depth int) ([]byte, bool) {
	if depth > 16 || len(buffer) > metadataLabelMaxKeySize {
		return nil, false
	}
	switch typed := value.(type) {
	case string:
		return appendMetadataLabelString(buffer, typed)
	case mapstr.M:
		if typed == nil {
			return append(buffer, 'n'), true
		}
		var keyScratch [64]string
		keys := keyScratch[:0]
		if len(typed) > len(keyScratch) {
			keys = make([]string, 0, len(typed))
		}
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buffer = append(buffer, 'm')
		buffer = strconv.AppendInt(buffer, int64(len(typed)), 10)
		buffer = append(buffer, ':')
		for _, key := range keys {
			var supported bool
			buffer, supported = appendMetadataLabelString(buffer, key)
			if !supported {
				return nil, false
			}
			buffer, supported = appendMetadataLabelKey(buffer, typed[key], depth+1)
			if !supported {
				return nil, false
			}
		}
		return buffer, len(buffer) <= metadataLabelMaxKeySize
	default:
		return nil, false
	}
}

func appendMetadataLabelString(buffer []byte, value string) ([]byte, bool) {
	if len(value)+len(buffer) > metadataLabelMaxKeySize-32 {
		return nil, false
	}
	buffer = append(buffer, 's')
	buffer = strconv.AppendInt(buffer, int64(len(value)), 10)
	buffer = append(buffer, ':')
	return append(buffer, value...), true
}
