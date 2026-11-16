package connectiontest

import (
	"context"
	"net"
	"net/http"
	"time"
)

// BoundClient applies one total budget and a socket deadline to short-lived
// probe clients. A tunnel's blocked TLS close must not outlive the UI timeout.
// Normal VPN traffic and shared application transports are never modified.
func BoundClient(client *http.Client, budget time.Duration) {
	if budget <= 0 {
		return
	}
	client.Timeout = budget
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return
	}
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: budget}).DialContext
	}
	deadline := time.Now().Add(budget)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if err = conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}
