package helper

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/stretchr/testify/require"
)

func TestHTTPFetchContentLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, strings.Repeat("x", 16))
	}))
	defer server.Close()
	client, err := NewHTTPFromConfig(defaultConfig(), mb.HostData{SanitizedURI: server.URL})
	require.NoError(t, err)
	content, err := client.FetchContentWithLimit(8)
	require.Error(t, err)
	require.Nil(t, content)
	content, err = client.FetchContentWithLimit(16)
	require.NoError(t, err)
	require.Len(t, content, 16)
	content, err = client.FetchContent()
	require.NoError(t, err)
	require.Len(t, content, 16)
}
