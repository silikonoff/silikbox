package bootstrapdns

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	singService "github.com/sagernet/sing/service"
)

func productionFixture(t *testing.T, system SystemFactory) *Transport {
	t.Helper()
	outs := outbound.NewRegistry()
	direct.RegisterOutbound(outs)
	registry := dns.NewTransportRegistry()
	Register(registry, system)
	ctx := box.Context(context.Background(), inbound.NewRegistry(), outs, endpoint.NewRegistry(), registry, service.NewRegistry(), certificate.NewRegistry())
	var options option.Options
	if err := options.UnmarshalJSONContext(ctx, []byte(`{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}],"dns":{"servers":[{"type":"silikbox-bootstrap","tag":"bootstrap","domains":["example.com"],"system_fallback":true}],"final":"bootstrap"}}`)); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	transport, found := singService.FromContext[adapter.DNSTransportManager](ctx).Transport("bootstrap")
	if !found {
		t.Fatal("transport missing")
	}
	return transport.(*Transport)
}

func TestProductionTransportLifecycle(t *testing.T) {
	r := productionFixture(t, func(ctx context.Context, logger log.ContextLogger, tag string) (adapter.DNSTransport, error) {
		return local.NewTransport(ctx, logger, tag, option.LocalDNSServerOptions{})
	})
	if len(r.stages) != 3 || len(r.stages[0].transports) != 2 || len(r.stages[1].transports) != 2 {
		t.Fatal("incomplete production policy")
	}
	r.Reset()
}

// Optional on-device test: real Google HTTPS and Cloudflare UDP/TCP transports
// from the shipped module, then the OS resolver. Faults affect only this test
// object's in-memory stages; no phone/VPN/network settings are changed.
func TestLiveAndroidFallback(t *testing.T) {
	if os.Getenv("SILIKBOX_DNS_LIVE") != "1" {
		t.Skip("opt-in live network test")
	}
	var systemCalls int
	system := func(_ context.Context, _ log.ContextLogger, _ string) (adapter.DNSTransport, error) {
		return &fakeResolver{exchange: func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
			systemCalls++
			network := "ip4"
			if q.Question[0].Qtype == mDNS.TypeAAAA {
				network = "ip6"
			}
			addresses, err := net.DefaultResolver.LookupIP(ctx, network, q.Question[0].Name)
			if err != nil {
				return nil, err
			}
			response := new(mDNS.Msg)
			response.SetReply(q)
			for _, ip := range addresses {
				if ip4 := ip.To4(); ip4 != nil {
					response.Answer = append(response.Answer, &mDNS.A{Hdr: mDNS.RR_Header{Name: q.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60}, A: ip4})
				}
			}
			return response, nil
		}}, nil
	}
	r := productionFixture(t, system)
	live := func(label string) {
		t.Helper()
		q := new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA)
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
		defer cancel()
		before := time.Now()
		response, err := r.Exchange(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if response.Rcode != mDNS.RcodeSuccess || len(response.Answer) == 0 {
			t.Fatalf("%s: no address", label)
		}
		t.Logf("%s PASS elapsed_ms=%d", label, time.Since(before).Milliseconds())
	}
	// Isolate each stage to prove actual network availability instead of accepting
	// a hidden success from its backup.
	original := append([]stage(nil), r.stages...)
	r.stages = original[:1]
	live("Google DoH certificate verified")
	r.stages = original[1:2]
	live("Cloudflare ordinary DNS")
	r.stages = original[2:]
	live("system DNS")
	// A silent first stage must time out before the real Cloudflare stage runs.
	silent := &fakeResolver{exchange: func(ctx context.Context, _ *mDNS.Msg) (*mDNS.Msg, error) { <-ctx.Done(); return nil, ctx.Err() }}
	r.stages = []stage{{name: "test-blocked Google", budget: 100 * time.Millisecond, transports: []adapter.DNSTransport{silent}}, original[1], original[2]}
	beforeCalls := systemCalls
	live("Google blocked -> Cloudflare")
	if systemCalls != beforeCalls {
		t.Fatal("system used while Cloudflare worked")
	}
	r.stages = []stage{{name: "test-blocked Google", budget: 100 * time.Millisecond, transports: []adapter.DNSTransport{silent}}, {name: "test-blocked Cloudflare", budget: 100 * time.Millisecond, transports: []adapter.DNSTransport{silent}}, original[2]}
	live("Google and Cloudflare blocked -> system")
	if systemCalls != beforeCalls+1 {
		t.Fatal("system backup did not run")
	}
	r.stages = original
}
