package state_cronjob

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	mbtest "github.com/elastic/beats/v7/metricbeat/mb/testing"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/require"
)

func TestCronJobInfoJoinsGaugeWithOptionalScheduleLabels(test *testing.T) {
	name, namespace, schedule, concurrency := "backup", "production", "0 * * * *", "Forbid"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = fmt.Fprint(writer, "# TYPE kube_cronjob_status_active gauge\nkube_cronjob_status_active{cronjob=\"backup\",namespace=\"production\"} 3\n# TYPE kube_cronjob_info gauge\nkube_cronjob_info{cronjob=\"backup\",namespace=\"production\",schedule=\"0 * * * *\",concurrency_policy=\"Forbid\"} 1\n")
	}))
	defer server.Close()
	fetcher := mbtest.NewFetcher(test, map[string]interface{}{"module": "kubernetes", "metricsets": []string{"state_cronjob"}, "hosts": []string{server.URL}, "add_metadata": false})
	events, failures := fetcher.FetchEvents()
	require.Empty(test, failures)
	require.Len(test, events, 1)
	require.Equal(test, mapstr.M{"name": name, "active": mapstr.M{"count": 3.0}, "schedule": schedule, "concurrency": concurrency}, events[0].MetricSetFields)
	require.Equal(test, namespace, events[0].ModuleFields["namespace"])
}
