package configcompat

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Only the normal Android builder supplies this marker. Raw/custom core configs
// retain their resolver policy. Nothing here writes the persisted profile.
func bootstrapDNS(config object, explicitRouteResolver bool) error {
	marker, present := config["_silikbox_bootstrap_dns"]
	delete(config, "_silikbox_bootstrap_dns")
	if !present || marker == nil || marker == false {
		return nil
	}
	policy := obj(marker)
	if policy == nil {
		return fmt.Errorf("invalid silikbox bootstrap policy")
	}
	d := obj(config["dns"])
	if d == nil {
		return nil
	}
	// Google endpoint IPs avoid a second bootstrap lookup. TLS still verifies
	// dns.google; the existing direct/proxy detour and query policy are retained.
	for _, raw := range list(d["servers"]) {
		s := obj(raw)
		if s["type"] == "https" && s["server"] == "dns.google" && (s["tag"] == "dns-direct" || s["tag"] == "dns-remote") && s["tls"] == nil {
			s["server"] = "8.8.4.4"
			s["tls"] = object{"enabled": true, "server_name": "dns.google"}
			delete(s, "domain_resolver")
		}
	}
	if explicitRouteResolver {
		return nil
	}
	tag := "silikbox-bootstrap"
	for _, raw := range list(d["servers"]) {
		if obj(raw)["tag"] == tag {
			return fmt.Errorf("reserved silikbox bootstrap DNS tag already exists")
		}
	}
	names := map[string]bool{}
	var targets []object
	for _, raw := range list(config["outbounds"]) {
		o := obj(raw)
		if o["domain_resolver"] != nil || o["detour"] != nil {
			continue
		}
		switch str(o["type"]) {
		case "direct", "block", "dns", "selector", "urltest":
			continue
		}
		name := str(o["server"])
		if name != "" && net.ParseIP(strings.Trim(name, "[]")) == nil {
			names[strings.ToLower(strings.TrimSuffix(name, "."))] = true
			targets = append(targets, o)
		}
	}
	for _, raw := range list(config["endpoints"]) {
		e := obj(raw)
		if e["type"] != "wireguard" || e["domain_resolver"] != nil || e["detour"] != nil {
			continue
		}
		needed := false
		for _, p := range list(e["peers"]) {
			name := str(obj(p)["address"])
			if name != "" && net.ParseIP(strings.Trim(name, "[]")) == nil {
				names[strings.ToLower(strings.TrimSuffix(name, "."))] = true
				needed = true
			}
		}
		if needed {
			targets = append(targets, e)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	domains := make([]string, 0, len(names))
	for name := range names {
		domains = append(domains, name)
	}
	sort.Strings(domains)
	for _, o := range targets {
		resolver := object{"server": tag}
		if inherited := obj(obj(config["route"])["default_domain_resolver"]); inherited != nil {
			for key, value := range inherited {
				if key != "server" {
					resolver[key] = value
				}
			}
		}
		o["domain_resolver"] = resolver
	}
	d["servers"] = append(list(d["servers"]), object{"type": tag, "tag": tag, "domains": domains, "system_fallback": policy["system_fallback"] == true})
	return nil
}
