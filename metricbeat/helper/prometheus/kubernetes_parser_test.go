package prometheus

import (
	"compress/gzip"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestKubernetesStreamingLabelsAndErrors(t *testing.T) {
	input := "# TYPE keep gauge\nignore{namespace=\"unused\"} 99\n" +
		"keep{ namespace=\"default\", detail=\"comma,quote\\\"slash\\\\line\\n\" } 1.5 123\n" +
		"keep{namespace=\"default\"} +Inf\n"
	client := &prometheus{httpfetcher: mockFetcher{response: input}, maxResponseBytes: 4096}
	families, err := client.GetFamiliesFor(map[string]struct{}{"keep": {}})
	require.NoError(t, err)
	require.Len(t, families, 1)
	require.Len(t, families[0].Metric, 2)
	require.Equal(t, 1.5, families[0].Metric[0].GetGauge().GetValue())
	values := map[string]string{}
	for _, label := range families[0].Metric[0].Label {
		values[label.GetName()] = label.GetValue()
	}
	require.Equal(t, map[string]string{"namespace": "default", "detail": "comma,quote\"slash\\line\n"}, values)
	for _, input := range []string{"keep{a=\"unterminated} 1", "keep{a=\"b\"} invalid"} {
		client.httpfetcher = mockFetcher{response: input}
		families, err := client.GetFamiliesFor(map[string]struct{}{"keep": {}})
		require.Error(t, err)
		require.Nil(t, families)
	}
}

func TestKubernetesStreamingBlocksAreIndependent(t *testing.T) {
	var input strings.Builder
	for index := 0; index < 6000; index++ {
		fmt.Fprintf(&input, "keep{namespace=\"default\",pod=\"pod-%d\"} %d\n", index, index)
	}
	client := &prometheus{httpfetcher: mockFetcher{response: input.String()}, maxResponseBytes: 1 << 20}
	families, err := client.GetFamiliesFor(map[string]struct{}{"keep": {}})
	require.NoError(t, err)
	require.Len(t, families, 1)
	require.Len(t, families[0].Metric, 6000)
	for index, metric := range families[0].Metric {
		require.Equal(t, float64(index), metric.GetGauge().GetValue())
		require.Equal(t, fmt.Sprintf("pod-%d", index), metric.Label[1].GetValue())
		require.Same(t, families[0].Metric[0].Label[0].Value, metric.Label[0].Value)
	}
}

func TestKubernetesStreamingNoLabelsAndExactLimit(t *testing.T) {
	input := "keep 1\nkeep NaN\nkeep -Inf"
	client := &prometheus{httpfetcher: mockFetcher{response: input}, maxResponseBytes: int64(len(input))}
	families, err := client.GetFamiliesFor(map[string]struct{}{"keep": {}})
	require.NoError(t, err)
	require.Len(t, families[0].Metric, 3)
	require.Empty(t, families[0].Metric[0].Label)
	require.True(t, math.IsNaN(families[0].Metric[1].GetGauge().GetValue()))
	require.True(t, math.IsInf(families[0].Metric[2].GetGauge().GetValue(), -1))
	client.maxResponseBytes--
	families, err = client.GetFamiliesFor(map[string]struct{}{"keep": {}})
	require.Error(t, err)
	require.Nil(t, families)
}

func TestKubernetesStreamingConcurrentSnapshots(t *testing.T) {
	client := &prometheus{httpfetcher: mockFetcher{response: "keep{namespace=\"default\"} 42\n"}, maxResponseBytes: 1024}
	selected := map[string]struct{}{"keep": {}}
	snapshots := make([][]*dto.MetricFamily, 8)
	errors := make([]error, len(snapshots))
	var workers sync.WaitGroup
	for index := range snapshots {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			snapshots[index], errors[index] = client.GetFamiliesFor(selected)
		}(index)
	}
	workers.Wait()
	for index, snapshot := range snapshots {
		require.NoError(t, errors[index])
		require.Len(t, snapshot, 1)
		require.Equal(t, float64(42), snapshot[0].Metric[0].GetGauge().GetValue())
		if index > 0 {
			require.NotSame(t, snapshots[0][0].Metric[0], snapshot[0].Metric[0])
		}
	}
}

func TestKubernetesStreamingLargeLineAndInvalidUTF8(t *testing.T) {
	value := strings.Repeat("x", 80<<10)
	client := &prometheus{httpfetcher: mockFetcher{response: "keep{label=\"" + value + "\"} 1\nkeep 2\n"}, maxResponseBytes: 128 << 10}
	families, err := client.GetFamiliesFor(map[string]struct{}{"keep": {}})
	require.NoError(t, err)
	require.Len(t, families[0].Metric, 2)
	require.Equal(t, value, families[0].Metric[0].Label[0].GetValue())
	require.Equal(t, float64(2), families[0].Metric[1].GetGauge().GetValue())
	client.httpfetcher = mockFetcher{response: "keep{label=\"\xff\"} 1\n"}
	families, err = client.GetFamiliesFor(map[string]struct{}{"keep": {}})
	require.Error(t, err)
	require.Nil(t, families)
}

type kubernetesGzipFetcher struct {
	input string
}

func (fetcher kubernetesGzipFetcher) FetchResponse() (*http.Response, error) {
	var compressed strings.Builder
	writer := gzip.NewWriter(&compressed)
	_, err := io.WriteString(writer, fetcher.input)
	if err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": []string{"gzip"}}, Body: io.NopCloser(strings.NewReader(compressed.String()))}, nil
}

func TestKubernetesStreamingLimitsAllBytesAndClosesBody(t *testing.T) {
	for _, input := range []string{strings.Repeat("#ignored\n", 300), "keep{label=\"" + strings.Repeat("x", 2000) + "\"} 1\n"} {
		client := &prometheus{httpfetcher: kubernetesGzipFetcher{input: input}, maxResponseBytes: 1024}
		families, err := client.GetFamiliesFor(map[string]struct{}{"keep": {}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "max_response_bytes")
		require.Nil(t, families)
	}
	body := &failedBody{}
	client := &prometheus{httpfetcher: failedBodyFetcher{body: body}}
	_, err := client.GetFamiliesFor(map[string]struct{}{"keep": {}})
	require.Error(t, err)
	require.True(t, body.closed)
}
