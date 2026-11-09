package util

import (
	"testing"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

type enricherTestMetricSet struct{ mb.BaseMetricSet }

func (*enricherTestMetricSet) Fetch(mb.ReporterV2) {}

type countingEnricher struct{ stops int }

func (*countingEnricher) Start()            {}
func (enricher *countingEnricher) Stop()    { enricher.stops++ }
func (*countingEnricher) Enrich([]mapstr.M) {}

func TestSharedEnricherReleasedOnlyAfterLastConsumer(t *testing.T) {
	registry := mb.NewRegister()
	registry.MustAddMetricSet("test", "dummy", func(base mb.BaseMetricSet) (mb.MetricSet, error) {
		return &enricherTestMetricSet{BaseMetricSet: base}, nil
	})
	conf, err := config.NewConfigFrom(map[string]interface{}{"module": "test", "metricsets": []string{"dummy"}, "hosts": []string{"node-a"}})
	require.NoError(t, err)
	_, sets, err := mb.NewModule(conf, registry)
	require.NoError(t, err)
	base := sets[0].(*enricherTestMetricSet).BaseMetricSet
	repo := NewMetricsRepo()
	created := 0
	underlying := &countingEnricher{}
	create := func() Enricher { created++; return underlying }
	first := acquireMetadataEnricher(base, "node", repo, false, create)
	second := acquireMetadataEnricher(base, "node", repo, false, create)
	require.Equal(t, 1, created)
	first.Stop()
	first.Stop()
	require.Zero(t, underlying.stops)
	second.Stop()
	require.Equal(t, 1, underlying.stops)
	require.Empty(t, repo.enrichers)
}
