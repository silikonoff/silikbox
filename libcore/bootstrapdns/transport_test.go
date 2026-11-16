package bootstrapdns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
)

type fakeResolver struct {
	dns.TransportAdapter
	calls    atomic.Int32
	exchange func(context.Context, *mDNS.Msg) (*mDNS.Msg, error)
}

func (f *fakeResolver) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (f *fakeResolver) Reset()                                         {}
func (f *fakeResolver) Exchange(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
	f.calls.Add(1)
	return f.exchange(ctx, q)
}
func (f *fakeResolver) ExchangeAsync(ctx context.Context, q *mDNS.Msg, cb func(*mDNS.Msg, error)) {
	cb(f.Exchange(ctx, q))
}

func answer(code int) func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return func(_ context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		r := new(mDNS.Msg)
		r.SetReply(q)
		r.Rcode = code
		return r, nil
	}
}
func unavailable(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return nil, errors.New("blocked by test")
}
func query() *mDNS.Msg {
	q := new(mDNS.Msg)
	q.SetQuestion("vpn.example.", mDNS.TypeA)
	q.Id = 173
	return q
}

func TestOrderedFallbackAndNegativePrivacy(t *testing.T) {
	for _, tc := range []struct {
		name               string
		google, cloudflare func(context.Context, *mDNS.Msg) (*mDNS.Msg, error)
		wantCF, wantSystem int32
		rcode              int
	}{
		{"primary", answer(mDNS.RcodeSuccess), unavailable, 0, 0, mDNS.RcodeSuccess},
		{"Google blocked", unavailable, answer(mDNS.RcodeSuccess), 1, 0, mDNS.RcodeSuccess},
		{"both blocked", unavailable, unavailable, 1, 1, mDNS.RcodeSuccess},
		{"NXDOMAIN stays encrypted", answer(mDNS.RcodeNameError), unavailable, 0, 0, mDNS.RcodeNameError},
		{"NODATA stays encrypted", answer(mDNS.RcodeSuccess), unavailable, 0, 0, mDNS.RcodeSuccess},
		{"REFUSED tries next", answer(mDNS.RcodeRefused), answer(mDNS.RcodeSuccess), 1, 0, mDNS.RcodeSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeResolver{exchange: tc.google}
			c := &fakeResolver{exchange: tc.cloudflare}
			s := &fakeResolver{exchange: answer(mDNS.RcodeSuccess)}
			r := &Transport{allowed: map[string]bool{"vpn.example.": true}, stages: []stage{
				{name: "Google", budget: time.Second, transports: []adapter.DNSTransport{g}},
				{name: "Cloudflare", budget: time.Second, transports: []adapter.DNSTransport{c}},
				{name: "system", budget: time.Second, transports: []adapter.DNSTransport{s}},
			}}
			q := query()
			response, err := r.Exchange(context.Background(), q)
			if err != nil || response.Rcode != tc.rcode || response.Id != q.Id {
				t.Fatalf("unexpected response/error: %v", err)
			}
			if g.calls.Load() != 1 || c.calls.Load() != tc.wantCF || s.calls.Load() != tc.wantSystem {
				t.Fatalf("wrong fallback order/privacy: %d/%d/%d", g.calls.Load(), c.calls.Load(), s.calls.Load())
			}
		})
	}
}

func TestBootstrapCannotResolveSitesOrOtherQuestionTypes(t *testing.T) {
	upstream := &fakeResolver{exchange: answer(mDNS.RcodeSuccess)}
	r := &Transport{allowed: map[string]bool{"vpn.example.": true}, stages: []stage{{budget: time.Second, transports: []adapter.DNSTransport{upstream}}}}
	for _, q := range []*mDNS.Msg{nil, new(mDNS.Msg), new(mDNS.Msg).SetQuestion("site.example.", mDNS.TypeA), new(mDNS.Msg).SetQuestion("vpn.example.", mDNS.TypeTXT)} {
		if _, err := r.Exchange(context.Background(), q); err == nil {
			t.Fatal("out-of-scope query accepted")
		}
	}
	if upstream.calls.Load() != 0 {
		t.Fatal("out-of-scope query escaped to network")
	}
	for _, kind := range []uint16{mDNS.TypeA, mDNS.TypeAAAA} {
		if _, err := r.Exchange(context.Background(), new(mDNS.Msg).SetQuestion("VPN.EXAMPLE.", kind)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStageTimeoutFallsThroughAndCancellationDoesNot(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "cancel"}[cancelParent], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g := &fakeResolver{exchange: func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
				if cancelParent {
					cancel()
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			c := &fakeResolver{exchange: answer(mDNS.RcodeSuccess)}
			r := &Transport{allowed: map[string]bool{"vpn.example.": true}, stages: []stage{{budget: 10 * time.Millisecond, transports: []adapter.DNSTransport{g}}, {budget: time.Second, transports: []adapter.DNSTransport{c}}}}
			_, err := r.Exchange(ctx, query())
			if cancelParent {
				if !errors.Is(err, context.Canceled) || c.calls.Load() != 0 {
					t.Fatal("cancelled query disclosed to backup")
				}
			} else if err != nil || c.calls.Load() != 1 {
				t.Fatal("timeout did not fall through")
			}
		})
	}
}

func TestRacingSameProviderCancelsLoser(t *testing.T) {
	stopped := make(chan struct{})
	slow := &fakeResolver{exchange: func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		defer close(stopped)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	fast := &fakeResolver{exchange: answer(mDNS.RcodeSuccess)}
	fallback := &fakeResolver{exchange: answer(mDNS.RcodeSuccess)}
	r := &Transport{allowed: map[string]bool{"vpn.example.": true}, stages: []stage{{budget: time.Second, transports: []adapter.DNSTransport{slow, fast}}, {budget: time.Second, transports: []adapter.DNSTransport{fallback}}}}
	if _, err := r.Exchange(context.Background(), query()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("loser not cancelled")
	}
	if fallback.calls.Load() != 0 {
		t.Fatal("later operator queried despite primary success")
	}
}

func TestInvalidResponseTriesBackupAndDisabledSystemStaysDisabled(t *testing.T) {
	wrong := &fakeResolver{exchange: func(_ context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		r := new(mDNS.Msg)
		r.SetReply(q)
		r.Question = append([]mDNS.Question(nil), q.Question...)
		r.Question[0].Name = "different.example."
		return r, nil
	}}
	c := &fakeResolver{exchange: answer(mDNS.RcodeSuccess)}
	r := &Transport{allowed: map[string]bool{"vpn.example.": true}, stages: []stage{{budget: time.Second, transports: []adapter.DNSTransport{wrong}}, {budget: time.Second, transports: []adapter.DNSTransport{c}}}}
	if _, err := r.Exchange(context.Background(), query()); err != nil || c.calls.Load() != 1 {
		t.Fatal("mismatched DNS answer accepted")
	}
	c.exchange = unavailable
	if _, err := r.Exchange(context.Background(), query()); err == nil {
		t.Fatal("unavailable providers unexpectedly succeeded")
	}
}
