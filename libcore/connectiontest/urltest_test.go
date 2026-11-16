package connectiontest

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matsuridayo/libneko/speedtest"
)

func TestRTTProbeReusesEstablishedTLSConnection(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 4096))) }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	if _, err := speedtest.UrlTest(server.Client(), server.URL, 2000, speedtest.UrlTestStandard_RTT); err != nil {
		t.Fatal(err)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("RTT measurement opened %d TLS connections; expected reuse of the first tunnel", got)
	}
}

func TestProbeTimeoutIncludesUnfinishedResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	BoundClient(client, 150*time.Millisecond)
	started := time.Now()
	if _, err := speedtest.UrlTest(client, server.URL, 150, speedtest.UrlTestStandard_RTT); err == nil {
		t.Fatal("unfinished response ignored the timeout")
	}
	if time.Since(started) > time.Second {
		t.Fatal("probe exceeded its bounded wait")
	}
}
