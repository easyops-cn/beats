package util

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

func TestMetadataLabelsShareIdenticalImmutableSubtrees(t *testing.T) {
	repo := NewMetricsRepo()
	first := repo.internMetadataLabels(sharedMetadataFixture())
	second := repo.internMetadataLabels(sharedMetadataFixture())
	require.Equal(t, first, second)
	firstK8s, secondK8s := first["kubernetes"].(mapstr.M), second["kubernetes"].(mapstr.M)
	require.Equal(t, fmt.Sprintf("%p", firstK8s["labels"]), fmt.Sprintf("%p", secondK8s["labels"]))
	require.Equal(t, fmt.Sprintf("%p", firstK8s["annotations"]), fmt.Sprintf("%p", secondK8s["annotations"]))
	require.Equal(t, fmt.Sprintf("%p", firstK8s["node"].(mapstr.M)["labels"]), fmt.Sprintf("%p", secondK8s["node"].(mapstr.M)["labels"]))
	require.Equal(t, fmt.Sprintf("%p", firstK8s["workload"]), fmt.Sprintf("%p", secondK8s["workload"]))
	before := first.Clone()
	legacy := &enricher{metadata: map[string]mapstr.M{"test": first}, index: func(mapstr.M) string { return "test" }}
	event := mapstr.M{}
	legacy.Enrich([]mapstr.M{event})
	_, err := event.Put("_module.labels.app.example.io/name", "changed")
	require.NoError(t, err)
	require.Equal(t, before, first)
	require.Equal(t, before, second)
}

func TestMetadataLabelKeysPreserveShapeAndTypes(t *testing.T) {
	interner := &metadataLabelInterner{}
	now := time.Now()
	values := []mapstr.M{
		{"a.b": "c"}, {"a": mapstr.M{"b": "c"}}, {"a": "bc"}, {"ab": "c"},
		{"empty": ""}, {"empty": mapstr.M{}}, {"empty": mapstr.M(nil)}, {"a": "b:c;m1:"},
	}
	keys := map[string]bool{}
	for _, value := range values {
		key, supported := appendMetadataLabelKey(nil, value, 0)
		require.True(t, supported)
		require.False(t, keys[string(key)], "signature collision")
		keys[string(key)] = true
		require.Equal(t, value, interner.intern(value, now))
	}
	for _, value := range []interface{}{1, true, nil, []string{"value"}, map[string]interface{}{"key": "value"}} {
		fields := mapstr.M{"nonstring": value}
		_, supported := appendMetadataLabelKey(nil, fields, 0)
		require.False(t, supported)
		require.Equal(t, fmt.Sprintf("%p", fields), fmt.Sprintf("%p", interner.intern(fields, now)))
	}
	first := interner.intern(mapstr.M{"b": "2", "a": "1"}, now)
	second := interner.intern(mapstr.M{"a": "1", "b": "2"}, now)
	require.Equal(t, fmt.Sprintf("%p", first), fmt.Sprintf("%p", second))
}

func TestMetadataLabelInternerBoundsEvictsAndExpires(t *testing.T) {
	interner := &metadataLabelInterner{}
	now := time.Now()
	for index := 0; index < metadataLabelMaxEntries*2; index++ {
		interner.intern(mapstr.M{"unique": fmt.Sprint(index)}, now)
	}
	require.Len(t, interner.entries, metadataLabelMaxEntries)
	for index := 0; index < 100; index++ {
		interner.intern(mapstr.M{"wide": strings.Repeat(fmt.Sprint(index%10), 32<<10) + fmt.Sprint(index)}, now)
		require.LessOrEqual(t, interner.keyBytes, metadataLabelKeyBudget)
		require.LessOrEqual(t, len(interner.entries), metadataLabelMaxEntries)
	}
	tooLarge := mapstr.M{"wide": strings.Repeat("x", metadataLabelMaxKeySize)}
	count := len(interner.entries)
	require.Equal(t, tooLarge, interner.intern(tooLarge, now))
	require.Len(t, interner.entries, count)
	interner.intern(mapstr.M{"active": "value"}, now.Add(metadataLabelIdleTTL))
	require.Len(t, interner.entries, 1)
	require.Equal(t, interner.recent.Len(), len(interner.entries))
	interner.intern(mapstr.M{"active": "value"}, now.Add(2*metadataLabelIdleTTL-time.Second))
	interner.intern(mapstr.M{"new": "value"}, now.Add(2*metadataLabelIdleTTL))
	require.Len(t, interner.entries, 2)
	recent := &metadataLabelInterner{}
	for index := 0; index < metadataLabelMaxEntries; index++ {
		recent.intern(mapstr.M{"key": fmt.Sprint(index)}, now)
	}
	recent.intern(mapstr.M{"key": "0"}, now.Add(time.Second))
	recent.intern(mapstr.M{"key": "replacement"}, now.Add(time.Second))
	first, supported := appendMetadataLabelKey(nil, mapstr.M{"key": "0"}, 0)
	require.True(t, supported)
	second, supported := appendMetadataLabelKey(nil, mapstr.M{"key": "1"}, 0)
	require.True(t, supported)
	require.Contains(t, recent.entries, string(first))
	require.NotContains(t, recent.entries, string(second))
	require.Len(t, recent.entries, metadataLabelMaxEntries)
	deep := mapstr.M{"leaf": "value"}
	for level := 0; level < 20; level++ {
		deep = mapstr.M{"nested": deep}
	}
	_, supported = appendMetadataLabelKey(nil, deep, 0)
	require.False(t, supported)
}

func TestMetadataLabelInternerConcurrentGeneration(t *testing.T) {
	repo := NewMetricsRepo()
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 50; iteration++ {
				result := repo.internMetadataLabels(sharedMetadataFixture())
				require.Equal(t, sharedMetadataFixture(), result)
				enrichment := &enricher{metadata: map[string]mapstr.M{"test": result}, index: func(mapstr.M) string { return "test" }}
				metadataPipelineEvent(t, enrichment, "state_deployment", true)
			}
		}()
	}
	workers.Wait()
	require.Len(t, repo.metadataLabels.entries, 3)
}

func BenchmarkMetadataLabelInternerHotLookup(b *testing.B) {
	for _, width := range []int{8, 32, 128} {
		b.Run(fmt.Sprint(width), func(b *testing.B) {
			fields := mapstr.M{}
			for label := 0; label < width; label++ {
				fields[fmt.Sprintf("label_%03d", label)] = strings.Repeat("v", 24)
			}
			interner := &metadataLabelInterner{}
			now := time.Now()
			interner.intern(fields, now)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				interner.intern(fields, now)
			}
		})
	}
}
