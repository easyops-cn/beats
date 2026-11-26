package prometheus

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

type ksmDiagnosticFetcher struct {
	path string
}

func (fetcher ksmDiagnosticFetcher) FetchResponse() (*http.Response, error) {
	file, err := os.Open(fetcher.path)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": []string{"gzip"}}, Body: file}, nil
}

func TestKSMMemoryDiagnostic(t *testing.T) {
	path := os.Getenv("KSM_MEMORY_INPUT")
	if path == "" {
		t.Skip("set KSM_MEMORY_INPUT to a local gzipped KSM snapshot")
	}
	mode := os.Getenv("KSM_MEMORY_MODE")
	var selected map[string]struct{}
	if selection := os.Getenv("KSM_MEMORY_SELECTED"); selection != "" {
		encoded, err := os.ReadFile(selection)
		require.NoError(t, err)
		var names []string
		require.NoError(t, json.Unmarshal(encoded, &names))
		selected = make(map[string]struct{}, len(names))
		for _, name := range names {
			selected[name] = struct{}{}
		}
	}
	require.Contains(t, []string{"read", "parse", "fetch", "fetch-two", "limit"}, mode)
	limit := int64(64 << 20)
	if configured := os.Getenv("KSM_MEMORY_LIMIT"); configured != "" {
		parsed, err := strconv.ParseInt(configured, 10, 64)
		require.NoError(t, err)
		require.Greater(t, parsed, int64(0))
		require.LessOrEqual(t, parsed, int64(1<<30))
		limit = parsed
	}
	readBody := func() []byte {
		file, err := os.Open(path)
		require.NoError(t, err)
		defer file.Close()
		reader, err := gzip.NewReader(file)
		require.NoError(t, err)
		defer reader.Close()
		body, err := io.ReadAll(io.LimitReader(reader, limit+1))
		require.NoError(t, err)
		require.LessOrEqual(t, int64(len(body)), limit)
		return body
	}
	var body []byte
	if mode == "parse" {
		body = readBody()
	}
	profile := func(suffix string) {
		if prefix := os.Getenv("KSM_MEMORY_PROFILE"); prefix != "" {
			require.NoError(t, os.MkdirAll(filepath.Dir(prefix), 0755))
			file, err := os.Create(prefix + suffix + ".pprof")
			require.NoError(t, err)
			require.NoError(t, pprof.WriteHeapProfile(file))
			require.NoError(t, file.Close())
		}
	}
	runtime.GC()
	profile("-before")
	var before, after, retained, released runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	var snapshots [][]*dto.MetricFamily
	switch mode {
	case "read":
		body = readBody()
	case "parse":
		snapshots = append(snapshots, NewParser().Parse(body))
	default:
		count := 1
		if mode == "fetch-two" {
			count = 2
		}
		for index := 0; index < count; index++ {
			client := &prometheus{httpfetcher: ksmDiagnosticFetcher{path: path}, parser: NewParser(), maxResponseBytes: limit}
			families, err := client.GetFamiliesFor(selected)
			if mode == "limit" {
				require.Error(t, err)
				require.True(t, strings.Contains(err.Error(), "exceeds max_response_bytes"))
				require.Empty(t, families)
			} else {
				require.NoError(t, err)
				snapshots = append(snapshots, families)
			}
		}
	}
	runtime.ReadMemStats(&after)
	elapsed := time.Since(start).Seconds()
	counts := map[string]int{}
	for _, families := range snapshots {
		counts["families"] += len(families)
		for _, family := range families {
			counts["samples"] += len(family.Metric)
			for _, metric := range family.Metric {
				counts["label_pairs"] += len(metric.Label)
			}
		}
	}
	if mode != "limit" && mode != "read" {
		require.Positive(t, counts["samples"])
	}
	runtime.GC()
	runtime.ReadMemStats(&retained)
	profile("-held")
	runtime.KeepAlive(snapshots)
	runtime.KeepAlive(body)
	snapshots, body = nil, nil
	runtime.GC()
	runtime.ReadMemStats(&released)
	profile("-released")
	result := map[string]interface{}{
		"mode": mode, "seconds": elapsed, "counts": counts,
		"allocated_bytes": after.TotalAlloc - before.TotalAlloc,
		"mallocs":         after.Mallocs - before.Mallocs, "gc_cycles": after.NumGC - before.NumGC,
		"before_heap_bytes": before.HeapAlloc, "end_heap_bytes": after.HeapAlloc,
		"held_post_gc_heap_bytes": retained.HeapAlloc, "released_post_gc_heap_bytes": released.HeapAlloc,
		"response_limit_bytes": limit,
	}
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	t.Logf("KSM_MEMORY %s", encoded)
}
