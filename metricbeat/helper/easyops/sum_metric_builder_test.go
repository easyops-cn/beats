package easyops

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

func TestStreamingSumMatchesGroupedSum(t *testing.T) {
	events := []mapstr.M{
		{"namespace": "a", "pod": mapstr.M{"name": "p"}, "metric": int64(3)},
		{"namespace": "a", "pod": mapstr.M{"name": "p"}, "metric": 0.5},
		{"namespace": "a", "pod": mapstr.M{"name": "p"}, "metric": -2.0},
		{"namespace": "b", "pod": mapstr.M{"name": "q"}},
		{"namespace": "b", "pod": mapstr.M{"name": "q"}, "metric": "not numeric"},
		{"namespace": "missing-pod", "metric": 100},
	}
	for _, dimensions := range [][]string{{"namespace"}, {"namespace", "pod.name"}, {}} {
		builder := newSumMetricBuilder("total.value", []string{"metric"}, dimensions, nil).(*sumMetricBuilder)
		var expected []mapstr.M
		for _, group := range GroupEventsByKeys(events, dimensions) {
			output := make(mapstr.M)
			for _, dimension := range dimensions {
				value, _ := group[0].GetValue(dimension)
				_, _ = output.Put(dimension, value)
			}
			_, _ = output.Put("total.value", builder.sum(group, builder.originMetrics))
			expected = append(expected, output)
		}
		canonical := func(values []mapstr.M) []string {
			var encoded []string
			for _, value := range values {
				data, err := json.Marshal(value)
				require.NoError(t, err)
				encoded = append(encoded, string(data))
			}
			sort.Strings(encoded)
			return encoded
		}
		require.Equal(t, canonical(expected), canonical(builder.Build(events)))
	}
}
