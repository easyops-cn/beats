package util

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

type batchEnricher struct{ sizes []int }

func (*batchEnricher) Start() {}
func (*batchEnricher) Stop()  {}
func (enricher *batchEnricher) Enrich(events []mapstr.M) {
	enricher.sizes = append(enricher.sizes, len(events))
	for _, event := range events {
		event["enriched"] = true
	}
}

func TestEnrichAndConsumeEventsBoundsMetadataAndReleasesInputs(t *testing.T) {
	for _, stopAfter := range []int{7, 600} {
		events := make([]mapstr.M, 600)
		for index := range events {
			events[index] = mapstr.M{"index": index}
		}
		enricher := &batchEnricher{}
		consumed := 0
		EnrichAndConsumeEvents(events, enricher, func(event mapstr.M) bool {
			require.Equal(t, consumed, event["index"])
			require.Equal(t, true, event["enriched"])
			require.Nil(t, events[consumed])
			consumed++
			return consumed < stopAfter
		})
		require.Equal(t, stopAfter, consumed)
		for _, size := range enricher.sizes {
			require.LessOrEqual(t, size, metadataEnrichmentBatchSize)
		}
		if stopAfter == len(events) {
			require.Equal(t, []int{256, 256, 88}, enricher.sizes)
		} else {
			require.NotNil(t, events[stopAfter])
		}
	}
}
