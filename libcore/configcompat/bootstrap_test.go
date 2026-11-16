package configcompat

import "testing"

func TestBootstrapOnlyResolvesProxyServers(t *testing.T) {
	m := normalized(t, `{"_silikbox_bootstrap_dns":{"system_fallback":true},"outbounds":[{"type":"vless","tag":"proxy","server":"vpn.example"},{"type":"direct","tag":"direct"}],"dns":{"servers":[{"tag":"dns-direct","address":"local","detour":"direct"},{"tag":"dns-remote","address":"https://dns.google/dns-query","detour":"proxy"}],"final":"dns-remote","rules":[{"outbound":["any"],"server":"dns-direct"}]}}`)
	if m["_silikbox_bootstrap_dns"] != nil {
		t.Fatal("private marker reached core schema")
	}
	proxy := obj(list(m["outbounds"])[0])
	resolver := obj(proxy["domain_resolver"])
	if str(resolver["server"]) != "silikbox-bootstrap" {
		t.Fatal("proxy still depends on a single bootstrap resolver")
	}
	d := obj(m["dns"])
	if d["final"] != "dns-remote" {
		t.Fatal("site DNS changed")
	}
	var found bool
	for _, raw := range list(d["servers"]) {
		s := obj(raw)
		if str(s["tag"]) == "silikbox-bootstrap" {
			found = true
			if s["type"] != "silikbox-bootstrap" || s["system_fallback"] != true || str(list(s["domains"])[0]) != "vpn.example" {
				t.Fatal("bootstrap scope/policy missing")
			}
		}
	}
	if !found {
		t.Fatal("bootstrap transport missing")
	}
}

func TestBootstrapPreservesExplicitResolversAndRawConfigs(t *testing.T) {
	for _, input := range []string{
		`{"outbounds":[{"type":"vless","server":"vpn.example"}],"dns":{"servers":[{"tag":"dns","type":"local"}]}}`,
		`{"_silikbox_bootstrap_dns":false,"outbounds":[{"type":"vless","server":"vpn.example"}],"dns":{"servers":[{"tag":"dns","type":"local"}]}}`,
		`{"_silikbox_bootstrap_dns":{"system_fallback":true},"outbounds":[{"type":"vless","server":"vpn.example","domain_resolver":{"server":"custom"}}],"dns":{"servers":[{"tag":"custom","type":"local"}]}}`,
		`{"_silikbox_bootstrap_dns":{"system_fallback":true},"route":{"default_domain_resolver":"custom"},"outbounds":[{"type":"vless","server":"vpn.example"}],"dns":{"servers":[{"tag":"custom","type":"local"}]}}`,
		`{"_silikbox_bootstrap_dns":{"system_fallback":true},"outbounds":[{"type":"vless","server":"192.0.2.1"}],"dns":{"servers":[{"tag":"custom","type":"local"}]}}`,
	} {
		m := normalized(t, input)
		if m["_silikbox_bootstrap_dns"] != nil {
			t.Fatal("private marker leaked")
		}
		for _, raw := range list(obj(m["dns"])["servers"]) {
			if obj(raw)["type"] == "silikbox-bootstrap" {
				t.Fatal("explicit/IP/raw configuration changed")
			}
		}
	}
}

func TestBootstrapWireguardScopeAndOptOut(t *testing.T) {
	m := normalized(t, `{"_silikbox_bootstrap_dns":{"system_fallback":false},"outbounds":[{"type":"vless","server":"192.0.2.1"}],"endpoints":[{"type":"wireguard","tag":"wg","peers":[{"address":"wg.example"},{"address":"192.0.2.2"}]}],"dns":{"servers":[{"type":"local","tag":"local"}]}}`)
	e := obj(list(m["endpoints"])[0])
	if obj(e["domain_resolver"])["server"] != "silikbox-bootstrap" {
		t.Fatal("WireGuard server was not covered")
	}
	s := obj(list(obj(m["dns"])["servers"])[1])
	if s["system_fallback"] != false || len(list(s["domains"])) != 1 || list(s["domains"])[0] != "wg.example" {
		t.Fatal("WireGuard scope/opt-out changed")
	}
}
