package util

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSharedMetadataWatcherLeasesAndIsolation(t *testing.T) {
	client := fake.NewSimpleClientset()
	config := &kubernetesConfig{KubeConfig: "shared-watcher-test"}
	options := kubernetes.WatchOptions{Node: "node-a", Namespace: "test"}
	first, err := newSharedMetadataWatcher(config, "test", client, &kubernetes.Pod{}, options)
	require.NoError(t, err)
	second, err := newSharedMetadataWatcher(config, "test", client, &kubernetes.Pod{}, options)
	require.NoError(t, err)
	require.Same(t, first.(*watcherLease).sharedMetadataWatcher, second.(*watcherLease).sharedMetadataWatcher)
	otherOptions := options
	otherOptions.Node = "node-b"
	other, err := newSharedMetadataWatcher(config, "test", client, &kubernetes.Pod{}, otherOptions)
	require.NoError(t, err)
	require.NotSame(t, first.(*watcherLease).sharedMetadataWatcher, other.(*watcherLease).sharedMetadataWatcher)
	var callsA, callsB int32
	first.AddEventHandler(kubernetes.ResourceEventHandlerFuncs{AddFunc: func(interface{}) { atomic.AddInt32(&callsA, 1) }})
	second.AddEventHandler(kubernetes.ResourceEventHandlerFuncs{AddFunc: func(interface{}) { atomic.AddInt32(&callsB, 1) }})
	var starters sync.WaitGroup
	for _, watcher := range []kubernetes.Watcher{first, second} {
		starters.Add(1)
		go func(watcher kubernetes.Watcher) {
			defer starters.Done()
			require.NoError(t, watcher.Start())
		}(watcher)
	}
	starters.Wait()
	first.(*watcherLease).dispatch(&kubernetes.Pod{}, "add")
	require.EqualValues(t, 1, atomic.LoadInt32(&callsA))
	require.EqualValues(t, 1, atomic.LoadInt32(&callsB))
	first.Stop()
	first.Stop()
	second.(*watcherLease).dispatch(&kubernetes.Pod{}, "add")
	require.EqualValues(t, 1, atomic.LoadInt32(&callsA))
	require.EqualValues(t, 2, atomic.LoadInt32(&callsB))
	second.Stop()
	other.Stop()
	metadataWatchers.Lock()
	_, remains := metadataWatchers.entries[first.(*watcherLease).key]
	metadataWatchers.Unlock()
	require.False(t, remains)
	replacement, err := newSharedMetadataWatcher(config, "test", client, &kubernetes.Pod{}, options)
	require.NoError(t, err)
	require.NotSame(t, first.(*watcherLease).sharedMetadataWatcher, replacement.(*watcherLease).sharedMetadataWatcher)
	replacement.Stop()
}

func TestMetadataResolvesNodeIPThroughSharedInformer(t *testing.T) {
	client := fake.NewSimpleClientset(&v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "actual-node-name"},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "172.30.5.241"}, {Type: v1.NodeInternalIP, Address: "2001:db8::1"}}},
	})
	watcher, err := newSharedMetadataWatcher(&kubernetesConfig{KubeConfig: "node-address-test"}, "test", client, &kubernetes.Node{}, kubernetes.WatchOptions{})
	require.NoError(t, err)
	defer watcher.Stop()
	for _, address := range []string{"172.30.5.241", "2001:db8::1"} {
		name, err := metadataNodeNameForAddress(address, watcher)
		require.NoError(t, err)
		require.Equal(t, "actual-node-name", name)
	}
	_, err = metadataNodeNameForAddress("172.30.5.242", watcher)
	require.Error(t, err)
}

func TestEnrichmentDoesNotAliasCachedMetadata(t *testing.T) {
	meta := mapstr.M{"kubernetes": mapstr.M{"namespace": "test", "pod": mapstr.M{"name": "pod-a"}}}
	enricher := &enricher{
		metadata:           map[string]mapstr.M{"pod-a": meta},
		index:              func(event mapstr.M) string { return "pod-a" },
		metadataTombstones: make(map[string]metadataTombstone),
	}
	events := []mapstr.M{{"value": 1}, {"value": 2}}
	enricher.Enrich(events)
	module := events[0]["_module"].(mapstr.M)
	module["namespace"] = "mutated"
	module["pod"].(mapstr.M)["name"] = "mutated"
	require.Equal(t, "test", events[1]["_module"].(mapstr.M)["namespace"])
	require.Equal(t, "pod-a", meta["kubernetes"].(mapstr.M)["pod"].(mapstr.M)["name"])
}

func TestEnrichmentConcurrentMetadataReplacement(t *testing.T) {
	enricher := &enricher{
		metadata: make(map[string]mapstr.M), metadataTombstones: make(map[string]metadataTombstone),
		index: func(event mapstr.M) string { return "pod-a" },
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for update := 0; update < 1000; update++ {
			enricher.Lock()
			enricher.metadata["pod-a"] = mapstr.M{"kubernetes": mapstr.M{"namespace": "test"}}
			enricher.cleanupMetadataTombstones(time.Now())
			enricher.Unlock()
		}
	}()
	for batch := 0; batch < 100; batch++ {
		enricher.Enrich([]mapstr.M{{"value": 1}, {"value": 2}})
	}
	workers.Wait()
}
