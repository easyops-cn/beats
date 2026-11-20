package kubernetes

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	p "github.com/elastic/beats/v7/metricbeat/helper/prometheus"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/mapstr"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

type sourceTestMetricSet struct{ mb.BaseMetricSet }

func (*sourceTestMetricSet) Fetch(mb.ReporterV2) {}

func TestStreamingCollectionUsesConfiguredMappingsAndLegacyRemainsSeparate(t *testing.T) {
	name := "state_source_test"
	mapping := &p.MetricsMapping{Metrics: map[string]p.MetricMap{"value": p.Metric("value")}}
	RegisterStateMetricsMapping(name, mapping)
	defer stateMetricMappings.Delete(name)
	registry := mb.NewRegister()
	require.NoError(t, registry.AddModule("kubernetes", ModuleBuilder()))
	require.NoError(t, registry.AddMetricSet("kubernetes", name, func(base mb.BaseMetricSet) (mb.MetricSet, error) {
		return &sourceTestMetricSet{base}, nil
	}))
	cfg, err := config.NewConfigFrom(map[string]interface{}{"module": "kubernetes", "hosts": []string{"http://ksm"}, "metricsets": []string{name}, "period": "1s", "add_metadata": false})
	require.NoError(t, err)
	created, _, err := mb.NewModule(cfg, registry)
	require.NoError(t, err)
	mod := created.(*module)
	mod.BeginStreamingCollection()
	require.NotNil(t, mod.compactState)
	require.Equal(t, []*p.MetricsMapping{mapping}, mod.compactMappings)
	mod.EndCollection()
	mod.BeginCollection()
	require.Nil(t, mod.compactState)
	require.Nil(t, mod.compactMappings)
	mod.EndCollection()
}

type sourceTestPrometheus struct {
	collectionPrometheus
	visits int32
	err    error
}

func (client *sourceTestPrometheus) VisitFamiliesFor(selected map[string]struct{}, consume func(string, *dto.Metric) error) error {
	atomic.AddInt32(&client.visits, 1)
	for _, family := range client.families {
		if _, exists := selected[family.GetName()]; exists {
			for _, sample := range family.Metric {
				if err := consume(family.GetName(), sample); err != nil {
					return err
				}
			}
		}
	}
	return client.err
}

func sourceTestModule(mappings ...*p.MetricsMapping) *module {
	mod := collectionTestModule()
	mod.BeginCollection()
	mod.compactMappings = mappings
	mod.compactState = make(map[string]*compactStateCache)
	mod.stateFamilies = make(map[string]struct{})
	for _, mapping := range mappings {
		for name := range mapping.Metrics {
			mod.stateFamilies[name] = struct{}{}
		}
	}
	return mod
}

func TestStreamingStateSourceSharesOneFetchAndKeepsRepeatedReads(t *testing.T) {
	first, second, value := "first", "second", float64(2)
	firstMapping := &p.MetricsMapping{Metrics: map[string]p.MetricMap{first: p.Metric("value")}}
	secondMapping := &p.MetricsMapping{Metrics: map[string]p.MetricMap{second: p.Metric("other")}}
	mod := sourceTestModule(firstMapping, secondMapping)
	defer mod.EndCollection()
	client := &sourceTestPrometheus{collectionPrometheus: collectionPrometheus{endpoint: "http://ksm-a:80/metrics", families: []*dto.MetricFamily{
		{Name: &first, Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &value}}}},
		{Name: &second, Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &value}}}},
	}}}
	var workers sync.WaitGroup
	for worker := 0; worker < 10; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for _, mapping := range []*p.MetricsMapping{firstMapping, secondMapping} {
				source, err := GetStateMetricsSource(mod, client, mapping)
				require.NoError(t, err)
				var events []mapstr.M
				source(func(batch []mapstr.M) bool { events = append(events, batch...); return true })
				require.Len(t, events, 1)
			}
		}()
	}
	workers.Wait()
	require.EqualValues(t, 1, client.visits)
	require.Zero(t, client.requests)
	require.Empty(t, mod.kubeStateMetricsCache.cacheMap)
	require.Len(t, mod.compactState, 1)
	mod.ReleaseCollectionEndpoint("other:80")
	require.Len(t, mod.compactState, 1)
	mod.ReleaseCollectionEndpoint("ksm-a:80")
	require.Empty(t, mod.compactState)
}

func TestStreamingStateSourceReleasesOnlyFinishedMappingConsumers(t *testing.T) {
	firstName, secondName, value := "state_release_first", "state_release_second", float64(2)
	firstMapping := &p.MetricsMapping{Metrics: map[string]p.MetricMap{firstName: p.Metric("value")}}
	secondMapping := &p.MetricsMapping{Metrics: map[string]p.MetricMap{secondName: p.Metric("other")}}
	RegisterStateMetricsMapping(firstName, firstMapping)
	RegisterStateMetricsMapping(secondName, secondMapping)
	defer stateMetricMappings.Delete(firstName)
	defer stateMetricMappings.Delete(secondName)
	mod := sourceTestModule(firstMapping, firstMapping, secondMapping)
	defer mod.EndCollection()
	client := &sourceTestPrometheus{collectionPrometheus: collectionPrometheus{endpoint: "http://ksm:80/metrics", families: []*dto.MetricFamily{
		{Name: &firstName, Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &value}}}},
		{Name: &secondName, Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &value}}}},
	}}}
	read := func(mapping *p.MetricsMapping) int {
		source, err := GetStateMetricsSource(mod, client, mapping)
		require.NoError(t, err)
		count := 0
		source(func(batch []mapstr.M) bool { count += len(batch); return true })
		return count
	}
	require.Equal(t, 1, read(firstMapping))
	mod.ReleaseCollectionMetricSet("other:80", firstName)
	require.Equal(t, 1, read(firstMapping))
	mod.ReleaseCollectionMetricSet("ksm:80", firstName)
	require.Equal(t, 1, read(firstMapping))
	mod.ReleaseCollectionMetricSet("ksm:80", firstName)
	require.Zero(t, read(firstMapping))
	require.Equal(t, 1, read(secondMapping))
	mod.ReleaseCollectionMetricSet("ksm:80", secondName)
	require.Zero(t, read(secondMapping))
	require.EqualValues(t, 1, client.visits)
}

func TestStreamingStateSourceDiscardsPartialSnapshotAndCachesError(t *testing.T) {
	name, value := "value", float64(2)
	mapping := &p.MetricsMapping{Metrics: map[string]p.MetricMap{name: p.Metric("value")}}
	mod := sourceTestModule(mapping)
	client := &sourceTestPrometheus{collectionPrometheus: collectionPrometheus{endpoint: "http://ksm/metrics", families: []*dto.MetricFamily{{Name: &name, Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &value}}}}}}, err: errors.New("truncated response")}
	for consumer := 0; consumer < 3; consumer++ {
		source, err := GetStateMetricsSource(mod, client, mapping)
		require.ErrorContains(t, err, "truncated response")
		require.Nil(t, source)
	}
	require.EqualValues(t, 1, client.visits)
	require.Nil(t, mod.compactState[client.endpoint].snapshot)
	mod.EndCollection()
	require.Nil(t, mod.compactState)
	mod = sourceTestModule(mapping)
	defer mod.EndCollection()
	client.err = nil
	source, err := GetStateMetricsSource(mod, client, mapping)
	require.NoError(t, err)
	require.NotNil(t, source)
	require.EqualValues(t, 2, client.visits)
}
