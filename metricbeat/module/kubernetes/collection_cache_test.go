package kubernetes

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastic/beats/v7/metricbeat/helper"
	p "github.com/elastic/beats/v7/metricbeat/helper/prometheus"
	"github.com/elastic/beats/v7/metricbeat/mb"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func collectionTestModule() *module {
	return &module{
		kubeStateMetricsCache: &kubeStateMetricsCache{cacheMap: make(map[uint64]*familiesCache)},
		kubeletStatsCache:     &kubeletStatsCache{cacheMap: make(map[uint64]*statsCache)},
		maxResponseBytes:      1024,
	}
}

func TestCollectionSummaryPinnedAndReleased(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&requests, 1)
		fmt.Fprint(writer, `{"node":{"nodeName":"node-1"},"pods":[]}`)
	}))
	defer server.Close()
	client, err := helper.NewHTTPFromConfig(helper.Config{}, mb.HostData{SanitizedURI: server.URL})
	require.NoError(t, err)
	mod := collectionTestModule()
	mod.BeginCollection()
	first, err := mod.GetKubeletSummary(client)
	require.NoError(t, err)
	for _, entry := range mod.kubeletStatsCache.cacheMap {
		entry.lastFetchTimestamp = time.Now().Add(-time.Hour)
	}
	var workers sync.WaitGroup
	for consumer := 0; consumer < 20; consumer++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			summary, err := mod.GetKubeletSummary(client)
			require.NoError(t, err)
			require.Same(t, first, summary)
		}()
	}
	workers.Wait()
	require.EqualValues(t, 1, atomic.LoadInt32(&requests))
	mod.EndCollection()
	require.Empty(t, mod.kubeletStatsCache.cacheMap)
	mod.BeginCollection()
	_, err = mod.GetKubeletSummary(client)
	require.NoError(t, err)
	require.EqualValues(t, 2, atomic.LoadInt32(&requests))
	mod.EndCollection()
}

func TestCollectionSummaryDifferentEndpointsConcurrent(t *testing.T) {
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		arrived <- struct{}{}
		<-release
		fmt.Fprint(writer, `{}`)
	}))
	defer server.Close()
	mod := collectionTestModule()
	mod.BeginCollection()
	var workers sync.WaitGroup
	for endpoint := 0; endpoint < 2; endpoint++ {
		client, err := helper.NewHTTPFromConfig(helper.Config{}, mb.HostData{SanitizedURI: fmt.Sprintf("%s/%d", server.URL, endpoint)})
		require.NoError(t, err)
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, err := mod.GetKubeletSummary(client)
			require.NoError(t, err)
		}()
	}
	concurrent := true
	for endpoint := 0; endpoint < 2; endpoint++ {
		select {
		case <-arrived:
		case <-time.After(3 * time.Second):
			concurrent = false
		}
	}
	close(release)
	workers.Wait()
	require.True(t, concurrent)
	mod.EndCollection()
}

func TestCollectionSummaryCachesErrorOnlyWithinRun(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&requests, 1)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := helper.NewHTTPFromConfig(helper.Config{}, mb.HostData{SanitizedURI: server.URL})
	require.NoError(t, err)
	mod := collectionTestModule()
	for run := 1; run <= 2; run++ {
		mod.BeginCollection()
		for consumer := 0; consumer < 4; consumer++ {
			summary, err := mod.GetKubeletSummary(client)
			require.Error(t, err)
			require.Nil(t, summary)
		}
		require.EqualValues(t, run, atomic.LoadInt32(&requests))
		mod.EndCollection()
	}
}

type collectionPrometheus struct {
	p.Prometheus
	endpoint string
	families []*dto.MetricFamily
	requests int32
}

func (client *collectionPrometheus) Endpoint() string { return client.endpoint }
func (client *collectionPrometheus) GetFamilies() ([]*dto.MetricFamily, error) {
	atomic.AddInt32(&client.requests, 1)
	return client.families, nil
}

func TestCollectionStateFamiliesIndexedOnceAndEndpointIsolated(t *testing.T) {
	keep, ignore := "keep", "ignore"
	client := &collectionPrometheus{endpoint: "ksm-a", families: []*dto.MetricFamily{{Name: &keep}, {Name: &ignore}}}
	other := &collectionPrometheus{endpoint: "ksm-b", families: []*dto.MetricFamily{{Name: &ignore}}}
	mod := collectionTestModule()
	mod.BeginCollection()
	mapping := &p.MetricsMapping{Metrics: map[string]p.MetricMap{"keep": p.Metric("value")}}
	for consumer := 0; consumer < 7; consumer++ {
		families, err := mod.GetStateMetricsFamiliesFor(client, mapping)
		require.NoError(t, err)
		require.Len(t, families, 1)
		require.Same(t, client.families[0], families[0])
	}
	otherFamilies, err := mod.GetStateMetricsFamiliesFor(other, mapping)
	require.NoError(t, err)
	require.Empty(t, otherFamilies)
	require.EqualValues(t, 1, client.requests)
	require.EqualValues(t, 1, other.requests)
	mod.EndCollection()
	require.Empty(t, mod.kubeStateMetricsCache.cacheMap)
}

func TestCollectionCacheFallbackBoundedAndExpiresIdleEntries(t *testing.T) {
	mod := collectionTestModule()
	for endpoint := uint64(0); endpoint < 2*collectionCacheMaxEntries; endpoint++ {
		mod.kubeletStatsCache.getCacheMapEntry(endpoint)
		mod.kubeStateMetricsCache.getCacheMapEntry(endpoint)
	}
	require.Len(t, mod.kubeletStatsCache.cacheMap, collectionCacheMaxEntries)
	require.Len(t, mod.kubeStateMetricsCache.cacheMap, collectionCacheMaxEntries)
	for _, entry := range mod.kubeletStatsCache.cacheMap {
		entry.lastAccessTimestamp = time.Now().Add(-time.Hour)
	}
	for _, entry := range mod.kubeStateMetricsCache.cacheMap {
		entry.lastAccessTimestamp = time.Now().Add(-time.Hour)
	}
	mod.kubeletStatsCache.getCacheMapEntry(1000)
	mod.kubeStateMetricsCache.getCacheMapEntry(1000)
	require.Len(t, mod.kubeletStatsCache.cacheMap, 1)
	require.Len(t, mod.kubeStateMetricsCache.cacheMap, 1)
}

type filteredCollectionPrometheus struct {
	collectionPrometheus
	selected map[string]struct{}
}

func (client *filteredCollectionPrometheus) GetFamiliesFor(selected map[string]struct{}) ([]*dto.MetricFamily, error) {
	client.selected = selected
	families, err := client.GetFamilies()
	var filtered []*dto.MetricFamily
	for _, family := range families {
		if _, exists := selected[family.GetName()]; exists {
			filtered = append(filtered, family)
		}
	}
	return filtered, err
}

func TestCollectionStateProjectionUsesUnionAndKeepsFullCacheSeparate(t *testing.T) {
	first, second, unused := "first", "second", "unused"
	RegisterStateMetricsMapping("state_test_first", &p.MetricsMapping{Metrics: map[string]p.MetricMap{first: p.Metric("value")}})
	RegisterStateMetricsMapping("state_test_second", &p.MetricsMapping{Metrics: map[string]p.MetricMap{second: p.Metric("value")}})
	defer stateMetricMappings.Delete("state_test_first")
	defer stateMetricMappings.Delete("state_test_second")
	mod := collectionTestModule()
	mod.stateFamilies = stateFamiliesFor([]string{"node", "state_test_first", "state_test_second"})
	require.Len(t, mod.stateFamilies, 2)
	require.Nil(t, stateFamiliesFor([]string{"state_test_first", "state_unknown"}))
	client := &filteredCollectionPrometheus{collectionPrometheus: collectionPrometheus{endpoint: "ksm", families: []*dto.MetricFamily{{Name: &first}, {Name: &second}, {Name: &unused}}}}
	mod.BeginCollection()
	defer mod.EndCollection()
	for _, name := range []string{second, first} {
		families, err := mod.GetStateMetricsFamiliesFor(client, &p.MetricsMapping{Metrics: map[string]p.MetricMap{name: p.Metric("value")}})
		require.NoError(t, err)
		require.Len(t, families, 1)
		require.Equal(t, name, families[0].GetName())
	}
	require.Len(t, client.selected, 2)
	require.EqualValues(t, 1, client.requests)
	all, err := mod.GetStateMetricsFamilies(client)
	require.NoError(t, err)
	require.Len(t, all, 3)
	require.EqualValues(t, 2, client.requests)
}
