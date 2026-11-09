package util

import (
	"fmt"
	"testing"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type incrementalMetadataStore struct {
	cache.Store
	reads int
}

func (store *incrementalMetadataStore) List() []interface{} {
	panic("metadata initialization must not expand every pod at once")
}

func (store *incrementalMetadataStore) ListKeys() []string {
	return append(store.Store.ListKeys(), "missing", "error")
}

func (store *incrementalMetadataStore) GetByKey(key string) (interface{}, bool, error) {
	store.reads++
	if key == "error" {
		return nil, false, fmt.Errorf("test read error")
	}
	return store.Store.GetByKey(key)
}

func TestMetadataInitializationExpandsOnePodAtATime(test *testing.T) {
	underlying := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for index := 0; index < 100; index++ {
		object, err := compactPodObject(&core.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: fmt.Sprint(index)}, Spec: core.PodSpec{Containers: []core.Container{{Name: "app"}}}})
		require.NoError(test, err)
		require.NoError(test, underlying.Add(object))
	}
	store := &incrementalMetadataStore{Store: expandedPodStore{underlying}}
	watcher := &mockWatcher{store: store}
	enricher := buildMetadataEnricher(watcher, nil, nil, func(metadata map[string]mapstr.M, resource kubernetes.Resource) []string {
		pod, ok := resource.(*core.Pod)
		require.True(test, ok)
		require.Equal(test, len(metadata)+1, store.reads)
		require.Equal(test, "app", pod.Spec.Containers[0].Name)
		metadata[pod.Name] = mapstr.M{"name": pod.Name}
		return []string{pod.Name}
	}, nil, nil)
	enricher.initializeMetadataFromStore()
	require.Len(test, enricher.metadata, 100)
	require.Equal(test, 102, store.reads)
}
