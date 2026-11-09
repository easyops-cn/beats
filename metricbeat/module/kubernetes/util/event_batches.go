package util

import (
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const metadataEnrichmentBatchSize = 256

type EventSource func(func([]mapstr.M) bool)

func EnrichAndConsumeSource(source EventSource, enricher Enricher, consume func(mapstr.M) bool, reporters ...mb.ReporterV2) {
	source(func(events []mapstr.M) bool {
		proceed := true
		EnrichAndConsumeEvents(events, enricher, func(event mapstr.M) bool {
			proceed = consume(event)
			return proceed
		}, reporters...)
		return proceed
	})
}

func EnrichAndConsumeEvents(events []mapstr.M, enricher Enricher, consume func(mapstr.M) bool, reporters ...mb.ReporterV2) {
	for start := 0; start < len(events); start += metadataEnrichmentBatchSize {
		end := start + metadataEnrichmentBatchSize
		if end > len(events) {
			end = len(events)
		}
		if enricher != nil {
			if len(reporters) > 0 {
				EnrichForReporter(enricher, events[start:end], reporters[0])
			} else {
				enricher.Enrich(events[start:end])
			}
		}
		for index := start; index < end; index++ {
			event := events[index]
			events[index] = nil
			if !consume(event) {
				return
			}
		}
	}
}
