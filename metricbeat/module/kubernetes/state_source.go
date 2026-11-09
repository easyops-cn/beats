package kubernetes

import (
	"net/url"
	"strings"
	"sync"

	p "github.com/elastic/beats/v7/metricbeat/helper/prometheus"
	"github.com/elastic/beats/v7/metricbeat/module/kubernetes/util"
	"github.com/elastic/elastic-agent-libs/mapstr"
	dto "github.com/prometheus/client_model/go"
)

type compactStateCache struct {
	lock      sync.Mutex
	snapshot  *p.KubernetesSnapshot
	err       error
	fetched   bool
	remaining map[*p.MetricsMapping]int
}

func (m *module) BeginStreamingCollection() {
	m.BeginCollection()
	m.kubeStateMetricsCache.lock.Lock()
	defer m.kubeStateMetricsCache.lock.Unlock()
	if m.stateFamilies == nil {
		return
	}
	for _, name := range m.Config().MetricSets {
		if strings.HasPrefix(name, "state_") {
			mapping, exists := stateMetricMappings.Load(name)
			if !exists {
				return
			}
			m.compactMappings = append(m.compactMappings, mapping.(*p.MetricsMapping))
		}
	}
	if _, supported := p.NewKubernetesSnapshot(m.compactMappings); supported {
		m.compactState = make(map[string]*compactStateCache)
	}
}

func GetStateMetricsSource(mod Module, client p.Prometheus, mapping *p.MetricsMapping) (util.EventSource, error) {
	if provider, ok := mod.(interface {
		compactStateSource(p.Prometheus, *p.MetricsMapping) (util.EventSource, bool, error)
	}); ok {
		if source, handled, err := provider.compactStateSource(client, mapping); handled {
			return source, err
		}
	}
	families, err := mod.GetStateMetricsFamiliesFor(client, mapping)
	if err != nil {
		return nil, err
	}
	events, err := client.ProcessMetrics(families, mapping)
	if err != nil {
		return nil, err
	}
	return func(consume func([]mapstr.M) bool) {
		for start := 0; start < len(events); start += 128 {
			end := start + 128
			if end > len(events) {
				end = len(events)
			}
			if !consume(events[start:end]) {
				return
			}
		}
	}, nil
}

func (m *module) compactStateSource(client p.Prometheus, mapping *p.MetricsMapping) (util.EventSource, bool, error) {
	visitor, supported := client.(interface {
		Endpoint() string
		VisitFamiliesFor(map[string]struct{}, func(string, *dto.Metric) error) error
	})
	if !supported {
		return nil, false, nil
	}
	m.kubeStateMetricsCache.lock.Lock()
	known := false
	for _, registered := range m.compactMappings {
		known = known || registered == mapping
	}
	if m.compactState == nil || !known {
		m.kubeStateMetricsCache.lock.Unlock()
		return nil, false, nil
	}
	endpoint := visitor.Endpoint()
	entry := m.compactState[endpoint]
	if entry == nil {
		entry = &compactStateCache{remaining: make(map[*p.MetricsMapping]int)}
		for _, registered := range m.compactMappings {
			entry.remaining[registered]++
		}
		m.compactState[endpoint] = entry
	}
	mappings := m.compactMappings
	m.kubeStateMetricsCache.lock.Unlock()
	entry.lock.Lock()
	defer entry.lock.Unlock()
	if !entry.fetched {
		snapshot, _ := p.NewKubernetesSnapshot(mappings)
		entry.err = visitor.VisitFamiliesFor(m.stateFamilies, snapshot.Add)
		if entry.err == nil {
			snapshot.Finish()
			entry.snapshot = snapshot
		}
		entry.fetched = true
	}
	if entry.err != nil {
		return nil, true, entry.err
	}
	snapshot := entry.snapshot
	return func(consume func([]mapstr.M) bool) {
		entry.lock.Lock()
		defer entry.lock.Unlock()
		// Plain state mappings do not need cross-row aggregation. Stream them in
		// bounded hash partitions so temporary selected maps and output batches
		// stay bounded. Keep the legacy whole-snapshot path for aggregate mappings
		// because their grouping state must see every row before it can emit a
		// result.
		if len(mapping.AggregateMetrics) == 0 {
			const partitions = 8
			// A source may be read repeatedly before the sampler reports the
			// metricset completion callback. Keep rows stable during reads and let
			// ReleaseCollectionMetricSet/ReleaseCollectionEndpoint perform final
			// reclamation.
			retain := true
			for partition := 0; partition < partitions; partition++ {
				accepted := true
				visit := snapshot.VisitPartition
				if retain {
					visit = snapshot.VisitPartitionRetain
				}
				visit(mapping, partition, partitions, func(batch []mapstr.M) bool {
					accepted = consume(batch)
					return accepted
				})
				if !accepted {
					return
				}
			}
			return
		}
		snapshot.Visit(mapping, consume)
	}, true, nil
}

func (m *module) ReleaseCollectionMetricSet(host, name string) {
	registered, exists := stateMetricMappings.Load(name)
	if !exists {
		return
	}
	mapping := registered.(*p.MetricsMapping)
	m.kubeStateMetricsCache.lock.Lock()
	defer m.kubeStateMetricsCache.lock.Unlock()
	for endpoint, entry := range m.compactState {
		address, err := url.Parse(endpoint)
		if err != nil || address.Host != host {
			continue
		}
		entry.lock.Lock()
		if entry.remaining[mapping] > 0 {
			entry.remaining[mapping]--
			if entry.remaining[mapping] == 0 && entry.snapshot != nil {
				entry.snapshot.Release(mapping)
			}
		}
		entry.lock.Unlock()
	}
}

func (m *module) ReleaseCollectionEndpoint(host string) {
	m.kubeStateMetricsCache.lock.Lock()
	for endpoint := range m.compactState {
		if address, err := url.Parse(endpoint); err == nil && address.Host == host {
			delete(m.compactState, endpoint)
		}
	}
	m.kubeStateMetricsCache.lock.Unlock()
	m.kubeletStatsCache.lock.Lock()
	if m.kubeletStatsCache.pinned {
		for key, entry := range m.kubeletStatsCache.cacheMap {
			if address, err := url.Parse(entry.endpoint); err == nil && address.Host == host {
				delete(m.kubeletStatsCache.cacheMap, key)
			}
		}
	}
	m.kubeletStatsCache.lock.Unlock()
}
