// Package bootstrapdns resolves only VPN endpoint names. Site DNS never uses
// this transport. Plaintext fallback is deliberately limited to that allowlist.
package bootstrapdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

const Type = "silikbox-bootstrap"

type Options struct {
	Domains        []string `json:"domains"`
	SystemFallback bool     `json:"system_fallback"`
}

type SystemFactory func(context.Context, log.ContextLogger, string) (adapter.DNSTransport, error)

func Register(registry *dns.TransportRegistry, system SystemFactory) {
	dns.RegisterTransport(registry, Type, func(ctx context.Context, logger log.ContextLogger, tag string, options Options) (adapter.DNSTransport, error) {
		return New(ctx, logger, tag, options, system)
	})
}

type stage struct {
	name       string
	budget     time.Duration
	transports []adapter.DNSTransport
}

type Transport struct {
	dns.TransportAdapter
	allowed map[string]bool
	stages  []stage
	logger  log.ContextLogger
}

var _ adapter.DNSTransport = (*Transport)(nil)

func New(ctx context.Context, logger log.ContextLogger, tag string, options Options, system SystemFactory) (*Transport, error) {
	t := &Transport{TransportAdapter: dns.NewTransportAdapter(Type, tag, nil), allowed: make(map[string]bool), logger: logger}
	for _, name := range options.Domains {
		name = strings.ToLower(mDNS.Fqdn(strings.TrimSpace(name)))
		if _, valid := mDNS.IsDomainName(name); !valid || name == "." {
			return nil, errors.New("invalid bootstrap domain")
		}
		t.allowed[name] = true
	}
	if len(t.allowed) == 0 {
		return nil, errors.New("empty bootstrap domain allowlist")
	}
	google := stage{name: "Google DoH", budget: 2500 * time.Millisecond}
	for _, ip := range []string{"8.8.4.4", "8.8.8.8"} {
		var opts option.RemoteHTTPSDNSServerOptions
		opts.Server = ip
		opts.TLS = &option.OutboundTLSOptions{Enabled: true, ServerName: "dns.google"}
		resolver, err := transport.NewHTTPS(ctx, logger, tag+"-google-"+ip, opts)
		if err != nil {
			return nil, err
		}
		google.transports = append(google.transports, resolver)
	}
	cloudflare := stage{name: "Cloudflare DNS", budget: 1500 * time.Millisecond}
	for _, ip := range []string{"1.1.1.1", "1.0.0.1"} {
		var opts option.RemoteDNSServerOptions
		opts.Server = ip
		resolver, err := transport.NewUDP(ctx, logger, tag+"-cloudflare-"+ip, opts)
		if err != nil {
			return nil, err
		}
		cloudflare.transports = append(cloudflare.transports, resolver)
	}
	t.stages = []stage{google, cloudflare}
	if options.SystemFallback {
		if system == nil {
			return nil, errors.New("system bootstrap resolver unavailable")
		}
		resolver, err := system(ctx, logger, tag+"-system")
		if err != nil {
			return nil, err
		}
		t.stages = append(t.stages, stage{name: "Android system DNS", budget: 3 * time.Second, transports: []adapter.DNSTransport{resolver}})
	}
	return t, nil
}

func (t *Transport) Start(phase adapter.StartStage, scope *adapter.Scope) error {
	for _, group := range t.stages {
		for _, resolver := range group.transports {
			if err := scope.Start(resolver.Tag(), resolver, phase); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *Transport) Reset() {
	for _, group := range t.stages {
		for _, resolver := range group.transports {
			resolver.Reset()
		}
	}
}

func (t *Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.Exchange(ctx, message)) }()
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if message == nil || len(message.Question) != 1 {
		return nil, errors.New("bootstrap requires one IP question")
	}
	q := message.Question[0]
	if q.Qclass != mDNS.ClassINET || (q.Qtype != mDNS.TypeA && q.Qtype != mDNS.TypeAAAA) || !t.allowed[strings.ToLower(mDNS.Fqdn(q.Name))] {
		return nil, errors.New("query outside VPN endpoint bootstrap scope")
	}
	for index, group := range t.stages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response, err := exchangeStage(ctx, message, group)
		if err == nil {
			if t.logger != nil {
				t.logger.DebugContext(ctx, "VPN endpoint DNS: ", group.name)
			}
			return response, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if index+1 < len(t.stages) && t.logger != nil {
			t.logger.DebugContext(ctx, "VPN endpoint DNS unavailable: ", group.name, "; trying next resolver")
		}
	}
	return nil, errors.New("VPN endpoint DNS: all permitted resolvers unavailable")
}

// Only addresses of one operator race each other. A later operator never sees
// the question until the preceding stage has failed. Cancelled calls cannot
// initiate plaintext fallback. Android raw queries may finish their bounded
// native poll after cancellation; the buffered channel prevents a blocked send.
func exchangeStage(parent context.Context, message *mDNS.Msg, group stage) (*mDNS.Msg, error) {
	ctx, cancel := context.WithTimeout(parent, group.budget)
	defer cancel()
	type result struct {
		response *mDNS.Msg
		err      error
	}
	results := make(chan result, len(group.transports))
	for _, resolver := range group.transports {
		query := message.Copy()
		query.Id = 0 // RFC 8484; each underlying transport validates its wire ID.
		go func(resolver adapter.DNSTransport) {
			response, err := resolver.Exchange(ctx, query)
			if err == nil {
				err = validateResponse(query, response)
			}
			results <- result{response, err}
		}(resolver)
	}
	for range group.transports {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-results:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if r.err == nil {
				r.response.Id = message.Id
				return r.response, nil
			}
		}
	}
	return nil, fmt.Errorf("%s unavailable", group.name)
}

func validateResponse(query, response *mDNS.Msg) error {
	if response == nil || !response.Response || response.Id != query.Id || response.Truncated || response.Opcode != mDNS.OpcodeQuery || len(response.Question) != 1 {
		return errors.New("invalid bootstrap DNS response")
	}
	expected, actual := query.Question[0], response.Question[0]
	if !strings.EqualFold(mDNS.Fqdn(expected.Name), mDNS.Fqdn(actual.Name)) || expected.Qtype != actual.Qtype || expected.Qclass != actual.Qclass {
		return errors.New("bootstrap DNS question mismatch")
	}
	// Negative answers are authoritative outcomes for this policy, not evidence
	// of a blocked transport. Never disclose NXDOMAIN/NODATA to another operator.
	if response.Rcode != mDNS.RcodeSuccess && response.Rcode != mDNS.RcodeNameError {
		return errors.New("bootstrap DNS server failure")
	}
	return nil
}
