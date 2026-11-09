package easyops

import "github.com/elastic/elastic-agent-libs/mapstr"

type sumMetricBuilder struct {
	baseBuilderFields
}

func newSumMetricBuilder(field string, originMetric []string, groupKeys []string, defaultValues map[string]interface{}) AggregateMetricBuilder {
	return &sumMetricBuilder{
		baseBuilderFields{
			field:         field,
			originMetrics: originMetric,
			groupKeys:     groupKeys,
			defaultValues: defaultValues,
		},
	}
}

func (builder *sumMetricBuilder) Build(events []mapstr.M) []mapstr.M {
	if len(builder.originMetrics) == 1 {
		return builder.buildSingleMetric(events)
	}
	var result []mapstr.M
	eventMap := GroupEventsByKeys(events, builder.groupKeys)
	for _, es := range eventMap {
		if len(es) == 0 {
			continue
		}
		rs := mapstr.M{}
		for _, groupKey := range builder.groupKeys {
			// GetValue success in GroupEventsByKeys
			val, _ := es[0].GetValue(groupKey)
			_, _ = rs.Put(groupKey, val)
		}
		_, _ = rs.Put(builder.field, builder.sum(es, builder.originMetrics))
		result = append(result, rs)
	}
	return result
}

func (builder *sumMetricBuilder) buildSingleMetric(events []mapstr.M) []mapstr.M {
	type groupSum struct {
		event mapstr.M
		value float64
	}
	groups := make(map[string]*groupSum)
	for _, event := range events {
		key, err := GenerateGroupValue(event, builder.groupKeys)
		if err != nil {
			continue
		}
		group := groups[key]
		if group == nil {
			group = &groupSum{event: make(mapstr.M)}
			for _, dimension := range builder.groupKeys {
				value, _ := event.GetValue(dimension)
				_, _ = group.event.Put(dimension, value)
			}
			groups[key] = group
		}
		if value, err := event.GetValue(builder.originMetrics[0]); err == nil {
			group.value += ConvertNumericValue(value)
		}
	}
	if len(groups) == 0 {
		return nil
	}
	result := make([]mapstr.M, 0, len(groups))
	for _, group := range groups {
		_, _ = group.event.Put(builder.field, group.value)
		result = append(result, group.event)
	}
	return result
}

func (builder *sumMetricBuilder) sum(events []mapstr.M, originMetric []string) interface{} {
	var floatResult float64 = 0
	for _, metric := range originMetric {
		for _, event := range events {
			value, err := event.GetValue(metric)
			if err == nil {
				floatResult += ConvertNumericValue(value)
			}
		}
	}
	return floatResult
}
