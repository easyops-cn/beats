package util

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

func TestMetadataTreeSharingPreservesShapesAndIsolation(t *testing.T) {
	pool := &metadataTreeInterner{}
	now := time.Now()
	fixture := func() mapstr.M {
		return mapstr.M{"kubernetes": mapstr.M{"namespace": "ns", "node": mapstr.M{"name": "node"}, "workload": mapstr.M{"name": "app"}, "empty": mapstr.M{}, "nil": mapstr.M(nil), "plain": map[string]interface{}{"key": "value"}, "number": 1}}
	}
	first, second := pool.share(fixture(), now), pool.share(fixture(), now)
	require.Equal(t, fixture(), first)
	firstK8s, secondK8s := first["kubernetes"].(mapstr.M), second["kubernetes"].(mapstr.M)
	require.Equal(t, fmt.Sprintf("%p", firstK8s["node"]), fmt.Sprintf("%p", secondK8s["node"]))
	require.Equal(t, fmt.Sprintf("%p", firstK8s["workload"]), fmt.Sprintf("%p", secondK8s["workload"]))
	require.NotEqual(t, fmt.Sprintf("%p", firstK8s), fmt.Sprintf("%p", secondK8s))
	cloned := first.Clone()
	_, err := cloned.Put("kubernetes.node.name", "changed")
	require.NoError(t, err)
	require.Equal(t, fixture(), second)
	for index := 0; index < 10000; index++ {
		pool.share(mapstr.M{"child": mapstr.M{"unique": fmt.Sprint(index)}}, now)
		require.LessOrEqual(t, pool.bytes, metadataTreeBudget)
		require.LessOrEqual(t, pool.recent.Len(), 4096)
	}
	pool.share(mapstr.M{}, now.Add(metadataLabelIdleTTL))
	require.Empty(t, pool.entries)
	require.Zero(t, pool.bytes)
	require.Equal(t, fixture(), first)
}

func TestMetadataTreeSharingConcurrentUpdates(t *testing.T) {
	pool := &metadataTreeInterner{}
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 100; iteration++ {
				meta := mapstr.M{"kubernetes": mapstr.M{"node": mapstr.M{"name": "node"}, "namespace": "ns"}}
				require.Equal(t, meta, pool.share(meta, time.Now()))
			}
		}()
	}
	workers.Wait()
}
