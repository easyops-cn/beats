package prometheus

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/pkg/textparse"
)

type kubernetesSample struct {
	metric dto.Metric
	gauge  dto.Gauge
	value  float64
}

func parseKubernetesFamilies(reader io.Reader, selected map[string]struct{}, maxBytes int64) ([]*dto.MetricFamily, error) {
	families := make([]*dto.MetricFamily, 0, len(selected))
	byName := make(map[string]*dto.MetricFamily, len(selected))
	stringsByValue := make(map[string]*string)
	intern := func(value string) *string {
		if stored, exists := stringsByValue[value]; exists {
			return stored
		}
		stored := strings.Clone(value)
		if len(value) <= 256 && len(stringsByValue) < 4096 {
			stringsByValue[stored] = &stored
		}
		return &stored
	}
	var sampleBlock []kubernetesSample
	var labelBlock []dto.LabelPair
	var pointerBlock []*dto.LabelPair
	var parsedLabels labels.Labels
	consume := func(body []byte) error {
		parser := textparse.NewPromParser(body)
		for {
			entry, err := parser.Next()
			if err == io.EOF {
				return nil
			}
			if err != nil || entry != textparse.EntrySeries {
				return fmt.Errorf("invalid Kubernetes metric sample: %v", err)
			}
			series, _, value := parser.Series()
			nameEnd := bytes.IndexByte(series, '{')
			if nameEnd < 0 {
				nameEnd = len(series)
			}
			name := bytes.TrimSpace(series[:nameEnd])
			parsedLabels = parsedLabels[:0]
			parser.Metric(&parsedLabels)
			if len(sampleBlock) == cap(sampleBlock) {
				sampleBlock = make([]kubernetesSample, 0, 256)
			}
			sampleBlock = sampleBlock[:len(sampleBlock)+1]
			sample := &sampleBlock[len(sampleBlock)-1]
			sample.value = value
			sample.gauge.Value = &sample.value
			sample.metric.Gauge = &sample.gauge
			labelCount := len(parsedLabels) - 1
			blockSize := 1024
			if labelCount > blockSize {
				blockSize = labelCount
			}
			if cap(labelBlock)-len(labelBlock) < labelCount {
				labelBlock = make([]dto.LabelPair, 0, blockSize)
			}
			if cap(pointerBlock)-len(pointerBlock) < labelCount {
				pointerBlock = make([]*dto.LabelPair, 0, blockSize)
			}
			pointerStart := len(pointerBlock)
			for _, label := range parsedLabels {
				if label.Name == labels.MetricName {
					continue
				}
				labelBlock = labelBlock[:len(labelBlock)+1]
				pair := &labelBlock[len(labelBlock)-1]
				pair.Name, pair.Value = intern(label.Name), intern(label.Value)
				pointerBlock = append(pointerBlock, pair)
			}
			sample.metric.Label = pointerBlock[pointerStart:len(pointerBlock):len(pointerBlock)]
			family := byName[string(name)]
			if family == nil {
				familyName := string(name)
				family = &dto.MetricFamily{Name: &familyName, Type: dto.MetricType_GAUGE.Enum()}
				byName[familyName] = family
				families = append(families, family)
			}
			family.Metric = append(family.Metric, &sample.metric)
		}
	}
	if err := scanKubernetesBatches(reader, selected, maxBytes, consume); err != nil {
		return nil, err
	}
	return families, nil
}

func visitKubernetesSamples(reader io.Reader, selected map[string]struct{}, maxBytes int64, consume func(string, *dto.Metric) error) error {
	var parsedLabels labels.Labels
	var pairs []dto.LabelPair
	var pointers []*dto.LabelPair
	return scanKubernetesBatches(reader, selected, maxBytes, func(body []byte) error {
		parser := textparse.NewPromParser(body)
		for {
			entry, err := parser.Next()
			if err == io.EOF {
				return nil
			}
			if err != nil || entry != textparse.EntrySeries {
				return fmt.Errorf("invalid Kubernetes metric sample: %v", err)
			}
			series, _, value := parser.Series()
			nameEnd := bytes.IndexByte(series, '{')
			if nameEnd < 0 {
				nameEnd = len(bytes.TrimSpace(series))
			}
			name := string(bytes.TrimSpace(series[:nameEnd]))
			parsedLabels = parsedLabels[:0]
			parser.Metric(&parsedLabels)
			if cap(pairs) < len(parsedLabels) {
				pairs = make([]dto.LabelPair, len(parsedLabels))
				pointers = make([]*dto.LabelPair, 0, len(parsedLabels))
			}
			pairs = pairs[:len(parsedLabels)]
			pointers = pointers[:0]
			for position := range parsedLabels {
				label := &parsedLabels[position]
				if label.Name == labels.MetricName {
					continue
				}
				pairs[position] = dto.LabelPair{Name: &label.Name, Value: &label.Value}
				pointers = append(pointers, &pairs[position])
			}
			metric := dto.Metric{Gauge: &dto.Gauge{Value: &value}, Label: pointers}
			if err := consume(name, &metric); err != nil {
				return err
			}
		}
	})
}

func scanKubernetesBatches(reader io.Reader, selected map[string]struct{}, maxBytes int64, consume func([]byte) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 16<<10), int(maxBytes)+1)
	const batchSize = 64 << 10
	batch := make([]byte, 0, batchSize+1)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := consume(batch)
		batch = batch[:0]
		return err
	}
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		nameEnd := bytes.IndexAny(line, "{ \t")
		if nameEnd < 0 {
			return fmt.Errorf("invalid Kubernetes metric sample")
		}
		if _, exists := selected[string(line[:nameEnd])]; !exists {
			continue
		}
		if len(batch)+len(line)+1 > batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
		if len(line)+1 > batchSize {
			if err := consume(line); err != nil {
				return err
			}
			continue
		}
		batch = append(batch, line...)
		batch = append(batch, '\n')
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("cannot read Kubernetes metrics: %w", err)
	}
	if err := flush(); err != nil {
		return err
	}
	return nil
}
