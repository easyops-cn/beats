package prometheus

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/elastic-agent-libs/mapstr"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestPrometheusLimitsDecompressedResponse(t *testing.T) {
	client := &prometheus{httpfetcher: mockFetcher{response: strings.Repeat("#", 2048)}, parser: NewParser(), maxResponseBytes: 1024}
	families, err := client.GetFamilies()
	require.Error(t, err)
	require.Contains(t, err.Error(), "max_response_bytes")
	require.Nil(t, families)
}

type failedBody struct {
	closed bool
}

func (*failedBody) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (body *failedBody) Close() error        { body.closed = true; return nil }

type failedBodyFetcher struct{ body *failedBody }

func (fetcher failedBodyFetcher) FetchResponse() (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: fetcher.body}, nil
}

func TestPrometheusPropagatesReadErrorAndClosesBody(t *testing.T) {
	body := &failedBody{}
	client := &prometheus{httpfetcher: failedBodyFetcher{body: body}, parser: NewParser()}
	families, err := client.GetFamilies()
	require.Error(t, err)
	require.Contains(t, err.Error(), "body read failed")
	require.Nil(t, families)
	require.True(t, body.closed)
}

func TestProcessMetricsMergesInfoByKeyWithoutEventIndexCopies(t *testing.T) {
	entity, version, entityValue, versionValue := "entity", "version", "app", "v1"
	gaugeName, infoName, value := "gauge", "info", float64(42)
	baseLabels := []*dto.LabelPair{{Name: &entity, Value: &entityValue}}
	families := []*dto.MetricFamily{
		{Name: &gaugeName, Metric: []*dto.Metric{{Label: baseLabels, Gauge: &dto.Gauge{Value: &value}}}},
		{Name: &infoName, Metric: []*dto.Metric{{Label: []*dto.LabelPair{baseLabels[0], {Name: &version, Value: &versionValue}}, Gauge: &dto.Gauge{Value: &value}}}},
	}
	client := &prometheus{}
	events, err := client.ProcessMetrics(families, &MetricsMapping{
		Metrics: map[string]MetricMap{"gauge": Metric("value"), "info": InfoMetric()},
		Labels:  map[string]LabelMap{"entity": KeyLabel("name"), "version": Label("version")},
	})
	require.NoError(t, err)
	require.Equal(t, []mapstr.M{{"name": "app", "value": float64(42), "version": "v1"}}, events)
}
