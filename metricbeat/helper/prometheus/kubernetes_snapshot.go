package prometheus

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"

	"github.com/elastic/beats/v7/metricbeat/helper/easyops"
	"github.com/elastic/elastic-agent-libs/mapstr"
	dto "github.com/prometheus/client_model/go"
)

type compactKubernetesRow struct {
	values []interface{}
	info   []uint64
	active bool
}

type compactKubernetesMapping struct {
	mapping *MetricsMapping
	keys    []string
	fields  []string
	indexes map[string]int
	rows    map[string]*compactKubernetesRow
	intern  func(string) string
}

type KubernetesSnapshot struct {
	mappings map[*MetricsMapping]*compactKubernetesMapping
	routes   map[string][]*compactKubernetesMapping
	strings  map[string]string
	bytes    int
}

func NewKubernetesSnapshot(mappings []*MetricsMapping) (*KubernetesSnapshot, bool) {
	snapshot := &KubernetesSnapshot{mappings: make(map[*MetricsMapping]*compactKubernetesMapping), routes: make(map[string][]*compactKubernetesMapping), strings: make(map[string]string)}
	for _, mapping := range mappings {
		if _, exists := snapshot.mappings[mapping]; exists {
			continue
		}
		for _, aggregate := range mapping.AggregateMetrics {
			if aggregate.Type != easyops.AggregateTypeSum && aggregate.Type != easyops.AggregateTypeCou {
				return nil, false
			}
		}
		compact := &compactKubernetesMapping{mapping: mapping, indexes: make(map[string]int), rows: make(map[string]*compactKubernetesRow), intern: snapshot.intern}
		for label, definition := range mapping.Labels {
			if definition.IsKey() {
				compact.keys = append(compact.keys, label)
			}
		}
		sort.Strings(compact.keys)
		for name, metric := range mapping.Metrics {
			switch metric.(type) {
			case *commonMetric, *keywordMetric, *booleanMetric, *labelMetric, *infoMetric:
			default:
				return nil, false
			}
			for _, option := range metric.GetOptions() {
				switch option.(type) {
				case opFilterMap, opLowercaseValue, opUnixTimestampValue, opLabelKeyPrefixRemover, opSetNumericMetricSuffix, opMultiplyBuckets:
				default:
					return nil, false
				}
			}
			snapshot.routes[name] = append(snapshot.routes[name], compact)
		}
		if !compact.prepareFields() {
			return nil, false
		}
		snapshot.mappings[mapping] = compact
	}
	return snapshot, true
}

func (mapping *compactKubernetesMapping) prepareFields() bool {
	fields := make(map[string]struct{})
	for _, label := range mapping.mapping.Labels {
		fields[label.GetField()] = struct{}{}
	}
	for _, metric := range mapping.mapping.Metrics {
		paths := []string{metric.GetField()}
		for _, option := range metric.GetOptions() {
			switch typed := option.(type) {
			case opFilterMap:
				var expanded []string
				for _, path := range paths {
					for _, suffix := range typed.filterMap {
						if path == "" {
							expanded = append(expanded, suffix)
						} else {
							expanded = append(expanded, path+"."+suffix)
						}
					}
				}
				paths = expanded
			case opSetNumericMetricSuffix:
				if _, numeric := metric.(*commonMetric); numeric {
					for position := range paths {
						paths[position] += "." + typed.suffix
					}
				}
			case opLabelKeyPrefixRemover:
				paths = nil
			}
		}
		for _, path := range paths {
			if path != "" {
				fields[path] = struct{}{}
			}
		}
		for path, value := range metric.GetConfiguration().ExtraFields {
			if value == nil {
				return false
			}
			switch value.(type) {
			case mapstr.M, map[string]interface{}:
				return false
			}
			fields[path] = struct{}{}
		}
	}
	for field := range fields {
		mapping.fields = append(mapping.fields, field)
	}
	sort.Strings(mapping.fields)
	for position, field := range mapping.fields {
		for parent := field; strings.Contains(parent, "."); {
			parent = parent[:strings.LastIndexByte(parent, '.')]
			if _, exists := fields[parent]; exists {
				return false
			}
		}
		mapping.indexes[field] = position
	}
	return true
}

func (snapshot *KubernetesSnapshot) intern(value string) string {
	if shared, exists := snapshot.strings[value]; exists {
		return shared
	}
	value = strings.Clone(value)
	if snapshot.strings != nil && len(value) <= 256 && len(snapshot.strings) < 4096 && snapshot.bytes+len(value) <= 1<<20 {
		snapshot.strings[value] = value
		snapshot.bytes += len(value)
	}
	return value
}

func (snapshot *KubernetesSnapshot) Finish() {
	snapshot.strings = nil
	for _, mapping := range snapshot.mappings {
		for key, row := range mapping.rows {
			if !row.active {
				delete(mapping.rows, key)
			}
		}
	}
}

func (snapshot *KubernetesSnapshot) Add(name string, sample *dto.Metric) error {
	for _, mapping := range snapshot.routes[name] {
		mapping.add(name, sample)
	}
	return nil
}

func (mapping *compactKubernetesMapping) add(name string, sample *dto.Metric) {
	definition := mapping.mapping.Metrics[name]
	field, value := definition.GetField(), definition.GetValue(sample)
	if value == nil {
		return
	}
	var labels mapstr.M
	for _, option := range definition.GetOptions() {
		if filter, ok := option.(opFilterMap); ok && labels == nil {
			text := getLabel(sample, filter.label)
			mapped, exists := filter.filterMap[text]
			if text == "" || !exists {
				return
			}
			if field == "" {
				field = mapped
			} else {
				field += "." + mapped
			}
			continue
		}
		if _, mutates := option.(opLabelKeyPrefixRemover); mutates && labels == nil {
			labels = getLabels(sample)
		}
		field, value, labels = option.Process(field, value, labels)
	}
	_, info := definition.(*infoMetric)
	if !info && field == "" {
		return
	}
	var identity strings.Builder
	for _, label := range mapping.keys {
		text := getLabel(sample, label)
		if labels != nil {
			text, _ = labels[label].(string)
		}
		if text != "" {
			identity.WriteString(strconv.Itoa(len(label)))
			identity.WriteByte(':')
			identity.WriteString(label)
			identity.WriteString(strconv.Itoa(len(text)))
			identity.WriteByte(':')
			identity.WriteString(text)
		}
	}
	key := identity.String()
	row := mapping.rows[key]
	if row == nil {
		row = &compactKubernetesRow{values: make([]interface{}, len(mapping.fields))}
		mapping.rows[key] = row
	}
	if !info {
		row.active = true
		mapping.put(row, field, value, false)
	}
	configuration := definition.GetConfiguration()
	putLabel := func(label string, text interface{}) {
		if mapped, exists := mapping.mapping.Labels[label]; exists {
			mapping.put(row, mapped.GetField(), text, info && !mapped.IsKey())
		} else if configuration.StoreNonMappedLabels {
			mapping.put(row, configuration.NonMappedLabelsPlacement+"."+label, text, info)
		}
	}
	if labels != nil {
		for label, text := range labels {
			putLabel(label, text)
		}
	} else {
		for _, label := range sample.Label {
			if label.GetName() != "" && label.GetValue() != "" {
				putLabel(label.GetName(), label.GetValue())
			}
		}
	}
	for extra, text := range configuration.ExtraFields {
		mapping.put(row, extra, text, info)
	}
}

func (mapping *compactKubernetesMapping) put(row *compactKubernetesRow, field string, value interface{}, info bool) {
	position, exists := mapping.indexes[field]
	if !exists {
		position = len(mapping.fields)
		mapping.indexes[field] = position
		mapping.fields = append(mapping.fields, field)
	}
	if position >= len(row.values) {
		row.values = append(row.values, make([]interface{}, position+1-len(row.values))...)
	}
	word, bit := position/64, uint64(1)<<uint(position%64)
	if word < len(row.info) && row.info[word]&bit != 0 && !info {
		return
	}
	if text, ok := value.(string); ok {
		if previous, ok := row.values[position].(string); ok && previous == text {
			value = previous
		} else {
			value = mapping.intern(text)
		}
	}
	row.values[position] = value
	if info {
		if word >= len(row.info) {
			row.info = append(row.info, make([]uint64, word+1-len(row.info))...)
		}
		row.info[word] |= bit
	}
}

func (snapshot *KubernetesSnapshot) Visit(mapping *MetricsMapping, consume func([]mapstr.M) bool) {
	compact := snapshot.mappings[mapping]
	if compact == nil {
		return
	}
	streams := make([]*kubernetesAggregateStream, len(mapping.AggregateMetrics))
	for position, definition := range mapping.AggregateMetrics {
		streams[position] = &kubernetesAggregateStream{definition: definition, groups: make(map[string]*kubernetesAggregateGroup)}
	}
	var batch []mapstr.M
	emit := func(event mapstr.M, start int) bool {
		for _, stream := range streams[start:] {
			stream.add(event)
		}
		if batch == nil {
			batch = make([]mapstr.M, 0, 128)
		}
		batch = append(batch, event)
		if len(batch) == cap(batch) {
			if !consume(batch) {
				return false
			}
			batch = nil
		}
		return true
	}
	for _, row := range compact.rows {
		if !row.active {
			continue
		}
		event := make(mapstr.M)
		for position, value := range row.values {
			if value != nil && !(position/64 < len(row.info) && row.info[position/64]&(uint64(1)<<uint(position%64)) != 0) {
				_, _ = event.Put(compact.fields[position], value)
			}
		}
		for field, value := range mapping.ExtraFields {
			event[field] = value
		}
		for position, value := range row.values {
			if position/64 < len(row.info) && row.info[position/64]&(uint64(1)<<uint(position%64)) != 0 {
				_, _ = event.Put(compact.fields[position], value)
			}
		}
		if !emit(event, 0) {
			return
		}
	}
	for position, stream := range streams {
		for _, group := range stream.groups {
			if stream.definition.Type == easyops.AggregateTypeSum {
				_, _ = group.event.Put(stream.definition.Field, group.sum)
			} else {
				for key, count := range group.counts {
					_, _ = group.event.Put(strings.Replace(stream.definition.Field, "{}", key, 1), count)
				}
			}
			if !emit(group.event, position+1) {
				return
			}
		}
		stream.groups = nil
	}
	if len(batch) > 0 {
		consume(batch)
	}
}

// VisitPartition streams one hash partition and releases its rows before
// returning. It is intended for mappings without cross-row aggregates; such
// mappings can therefore be consumed and submitted incrementally.
func (snapshot *KubernetesSnapshot) VisitPartition(mapping *MetricsMapping, partition, partitions int, consume func([]mapstr.M) bool) {
	snapshot.visitPartition(mapping, partition, partitions, consume, true)
}

// VisitPartitionRetain has the same bounded traversal as VisitPartition but
// keeps the compact rows for a repeated consumer. The owner can call Release
// once the final metricset consumer has completed its read.
func (snapshot *KubernetesSnapshot) VisitPartitionRetain(mapping *MetricsMapping, partition, partitions int, consume func([]mapstr.M) bool) {
	snapshot.visitPartition(mapping, partition, partitions, consume, false)
}

func (snapshot *KubernetesSnapshot) visitPartition(mapping *MetricsMapping, partition, partitions int, consume func([]mapstr.M) bool, release bool) {
	if partitions <= 1 || len(mapping.AggregateMetrics) != 0 {
		snapshot.Visit(mapping, consume)
		return
	}
	compact := snapshot.mappings[mapping]
	if compact == nil {
		return
	}
	selected := make(map[string]*compactKubernetesRow)
	hash := fnv.New32a()
	for key, row := range compact.rows {
		hash.Reset()
		_, _ = hash.Write([]byte(key))
		if int(hash.Sum32()%uint32(partitions)) == partition {
			selected[key] = row
		}
	}
	if len(selected) == 0 {
		return
	}
	original := compact.rows
	compact.rows = selected
	snapshot.Visit(mapping, consume)
	compact.rows = original
	if release {
		for key := range selected {
			delete(original, key)
		}
	}
}

func (snapshot *KubernetesSnapshot) Release(mapping *MetricsMapping) {
	if compact := snapshot.mappings[mapping]; compact != nil {
		compact.rows = nil
	}
}

type kubernetesAggregateGroup struct {
	event  mapstr.M
	sum    float64
	counts map[string]float64
}

type kubernetesAggregateStream struct {
	definition easyops.AggregateMetricMap
	groups     map[string]*kubernetesAggregateGroup
}

func (stream *kubernetesAggregateStream) add(event mapstr.M) {
	key, err := easyops.GenerateGroupValue(event, stream.definition.GroupKeys)
	if err != nil {
		return
	}
	group := stream.groups[key]
	if group == nil {
		group = &kubernetesAggregateGroup{event: make(mapstr.M)}
		for _, field := range stream.definition.GroupKeys {
			value, _ := event.GetValue(field)
			_, _ = group.event.Put(field, value)
		}
		if stream.definition.Type == easyops.AggregateTypeCou {
			group.counts = make(map[string]float64)
			for key, value := range stream.definition.DefaultValues {
				if number, ok := value.(float64); ok {
					group.counts[key] = number
				}
			}
		}
		stream.groups[key] = group
	}
	for _, field := range stream.definition.OriginMetrics {
		value, err := event.GetValue(field)
		if err != nil {
			continue
		}
		if stream.definition.Type == easyops.AggregateTypeSum {
			group.sum += easyops.ConvertNumericValue(value)
		} else {
			group.counts[strings.ToLower(fmt.Sprintf("%v", value))]++
		}
	}
}
