package prometheus

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/elastic/beats/v7/metricbeat/helper/easyops"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/golang/protobuf/proto"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func snapshotTestMapping() *MetricsMapping {
	return &MetricsMapping{
		Metrics: map[string]MetricMap{
			"info": InfoMetric(), "labels": ExtendedInfoMetric(Configuration{StoreNonMappedLabels: true, NonMappedLabelsPlacement: "labels", MetricProcessingOptions: []MetricOption{OpLabelKeyPrefixRemover("label_")}}),
			"usage": Metric("usage"), "ready": BooleanMetric("ready"), "phase": LabelMetric("phase", "phase"),
			"resources": Metric("", OpFilterMap("resource", map[string]string{"cpu": "cpu", "memory": "memory"})),
			"collision": Metric("version"),
		},
		Labels:      map[string]LabelMap{"namespace": KeyLabel("namespace"), "pod": KeyLabel("pod"), "node": Label("node"), "version": Label("version")},
		ExtraFields: map[string]string{"type": "pod"},
		AggregateMetrics: []easyops.AggregateMetricMap{
			{Type: easyops.AggregateTypeSum, Field: "node.cpu", OriginMetrics: []string{"cpu"}, GroupKeys: []string{"node"}},
			{Type: easyops.AggregateTypeSum, Field: "total", OriginMetrics: []string{"node.cpu"}},
			{Type: easyops.AggregateTypeCou, Field: "count.{}", OriginMetrics: []string{"ready"}, GroupKeys: []string{"node"}, DefaultValues: map[string]interface{}{"unknown": float64(2)}},
		},
	}
}

func TestKubernetesSnapshotMatchesLegacyJoinsAndAggregates(t *testing.T) {
	mapping := snapshotTestMapping()
	var body strings.Builder
	for entity := 0; entity < 300; entity++ {
		fmt.Fprintf(&body, "usage{namespace=\"ns\",pod=\"p%d\",node=\"n%d\"} %d\n", entity, entity%3, entity)
		fmt.Fprintf(&body, "ready{namespace=\"ns\",pod=\"p%d\"} %d\n", entity, entity%2)
		fmt.Fprintf(&body, "resources{namespace=\"ns\",pod=\"p%d\",resource=\"cpu\"} 2\nresources{namespace=\"ns\",pod=\"p%d\",resource=\"memory\"} 1024\n", entity, entity)
		fmt.Fprintf(&body, "resources{namespace=\"ns\",pod=\"p%d\",resource=\"ignored\"} 999\n", entity)
		fmt.Fprintf(&body, "phase{namespace=\"ns\",pod=\"p%d\",phase=\"running\"} 1\n", entity)
		fmt.Fprintf(&body, "collision{namespace=\"ns\",pod=\"p%d\",version=\"sample\"} 9\n", entity)
		fmt.Fprintf(&body, "info{namespace=\"ns\",pod=\"p%d\",version=\"v1\",node=\"n%d\"} 1\n", entity, entity%3)
		fmt.Fprintf(&body, "labels{namespace=\"ns\",pod=\"p%d\",label_app=\"app\",label_team=\"team\"} 1\n", entity)
	}
	body.WriteString("info{namespace=\"ns\",pod=\"info-only\"} 1\nusage{pod=\"missing-ns\"} 0\nusage{namespace=\"\",pod=\"empty-ns\"} 3\n")
	selected := make(map[string]struct{})
	for name := range mapping.Metrics {
		selected[name] = struct{}{}
	}
	families, err := parseKubernetesFamilies(strings.NewReader(body.String()), selected, 2<<20)
	require.NoError(t, err)
	expected, err := (&prometheus{}).ProcessMetrics(families, mapping)
	require.NoError(t, err)
	snapshot, supported := NewKubernetesSnapshot([]*MetricsMapping{mapping, mapping})
	require.True(t, supported)
	require.NoError(t, visitKubernetesSamples(strings.NewReader(body.String()), selected, 2<<20, snapshot.Add))
	snapshot.Finish()
	require.Nil(t, snapshot.strings)
	read := func() []mapstr.M {
		var events []mapstr.M
		snapshot.Visit(mapping, func(batch []mapstr.M) bool {
			require.LessOrEqual(t, len(batch), 128)
			events = append(events, batch...)
			return true
		})
		return events
	}
	require.ElementsMatch(t, expected, read())
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func() { defer workers.Done(); require.ElementsMatch(t, expected, read()) }()
	}
	workers.Wait()
	var batches int
	snapshot.Visit(mapping, func([]mapstr.M) bool { batches++; return false })
	require.Equal(t, 1, batches)
}

func TestKubernetesSnapshotVisitPartitionReleasesRows(t *testing.T) {
	name, value := "partition_value", float64(2)
	mapping := &MetricsMapping{Metrics: map[string]MetricMap{name: Metric("value")}, Labels: map[string]LabelMap{"namespace": KeyLabel("namespace")}}
	snapshot, supported := NewKubernetesSnapshot([]*MetricsMapping{mapping})
	require.True(t, supported)
	for index := 0; index < 32; index++ {
		metric := &dto.Metric{Gauge: &dto.Gauge{Value: &value}, Label: []*dto.LabelPair{{Name: proto.String("namespace"), Value: proto.String(fmt.Sprintf("ns-%d", index))}}}
		require.NoError(t, snapshot.Add(name, metric))
	}
	snapshot.Finish()
	seen := 0
	for partition := 0; partition < 4; partition++ {
		snapshot.VisitPartition(mapping, partition, 4, func(batch []mapstr.M) bool { seen += len(batch); return true })
	}
	require.Equal(t, 32, seen)
	require.Empty(t, snapshot.mappings[mapping].rows)
}

type snapshotResponseFetcher struct{ response *http.Response }

func (fetcher snapshotResponseFetcher) FetchResponse() (*http.Response, error) {
	return fetcher.response, nil
}

func TestKubernetesSampleVisitorLimitsGzipAndClosesBody(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, err := writer.Write([]byte(strings.Repeat("metric 1\n", 1000)))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	body := &snapshotCloseReader{Reader: bytes.NewReader(compressed.Bytes())}
	client := &prometheus{httpfetcher: snapshotResponseFetcher{&http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": []string{"gzip"}}, Body: body}}, maxResponseBytes: 1024}
	err = client.VisitFamiliesFor(map[string]struct{}{"metric": {}}, func(string, *dto.Metric) error { return nil })
	require.ErrorContains(t, err, "max_response_bytes")
	require.True(t, body.closed)
}

type snapshotCloseReader struct {
	io.Reader
	closed bool
}

func (reader *snapshotCloseReader) Close() error { reader.closed = true; return nil }

func TestKubernetesSnapshotRejectsUnsupportedAggregate(t *testing.T) {
	mapping := &MetricsMapping{Metrics: map[string]MetricMap{"value": Metric("value")}, AggregateMetrics: []easyops.AggregateMetricMap{{Type: easyops.AggregateTypeDiv}}}
	_, supported := NewKubernetesSnapshot([]*MetricsMapping{mapping})
	require.False(t, supported)
	mapping.AggregateMetrics = nil
	mapping.Metrics["parent"] = Metric("value.child")
	_, supported = NewKubernetesSnapshot([]*MetricsMapping{mapping})
	require.False(t, supported)
}
