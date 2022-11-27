package easyops

import (
	"fmt"
	"strings"

	"github.com/elastic/beats/v7/libbeat/common"
)

type couMetricBuilder struct {
	baseBuilderFields
}

func newCouMetricBuilder(field string, originMetric []string, groupKeys []string) AggregateMetricBuilder {
	return &couMetricBuilder{
		baseBuilderFields{
			field:         field,
			originMetrics: originMetric,
			groupKeys:     groupKeys,
		},
	}
}

func (builder *couMetricBuilder) Build(events []common.MapStr) []common.MapStr {
	var result []common.MapStr
	eventMap := GroupEventsByKeys(events, builder.groupKeys)
	for _, es := range eventMap {
		if len(es) == 0 {
			continue
		}
		rs := common.MapStr{}
		for _, groupKey := range builder.groupKeys {
			// GetValue success in GroupEventsByKeys
			val, _ := es[0].GetValue(groupKey)
			_, _ = rs.Put(groupKey, val)
		}
		counters := builder.count(es, builder.originMetrics)
		for val, count := range counters {
			field := strings.Replace(builder.field, "{}", val, 1)
			_, _ = rs.Put(field, count)
		}
		result = append(result, rs)
	}
	return result
}

func (builder *couMetricBuilder) count(events []common.MapStr, originMetric []string) map[string]float64 {
	counters := map[string]float64{}
	for _, metric := range originMetric {
		for _, event := range events {
			value, err := event.GetValue(metric)
			if err == nil {
				val := strings.ToLower(fmt.Sprintf("%v", value))
				if _, ok := counters[val]; !ok {
					counters[val] = 0
				}
				counters[val] += 1
			}
		}
	}
	return counters
}