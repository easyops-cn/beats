package util

import (
	"fmt"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

func TestMetadataTombstonesExpireAtEarliestDeadline(t *testing.T) {
	now := time.Now()
	enricher := &enricher{metadataTombstones: make(map[string]metadataTombstone)}
	for index := 0; index < 10000; index++ {
		enricher.metadataTombstones[fmt.Sprint(index)] = metadataTombstone{meta: mapstr.M{"value": index}, expiresAt: now.Add(time.Minute)}
	}
	enricher.metadataTombstones["earlier"] = metadataTombstone{expiresAt: now.Add(time.Second)}
	enricher.cleanupMetadataTombstones(now)
	require.Equal(t, now.Add(time.Second), enricher.nextMetadataCleanup)
	for update := 0; update < 10000; update++ {
		enricher.cleanupMetadataTombstones(now.Add(time.Millisecond))
	}
	require.Len(t, enricher.metadataTombstones, 10001)
	enricher.cleanupMetadataTombstones(now.Add(time.Second))
	require.Len(t, enricher.metadataTombstones, 10000)
	require.Equal(t, now.Add(time.Minute), enricher.nextMetadataCleanup)
	enricher.cleanupMetadataTombstones(now.Add(time.Minute))
	require.Empty(t, enricher.metadataTombstones)
	require.True(t, enricher.nextMetadataCleanup.IsZero())
}
