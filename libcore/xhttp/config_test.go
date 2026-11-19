package xhttp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	X "github.com/xtls/xray-core/core"
)

func fixtureOptions() Options {
	return Options{
		ServerOptions: option.ServerOptions{Server: "edge.example", ServerPort: 8443},
		UUID:          "00000000-0000-4000-8000-000000000001", Path: "/tunnel",
		Security: "reality", ServerName: "tls.example", Host: "http.example",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "0123456789abcdef",
		Extra: json.RawMessage(`{"mode":"stream-one","xPaddingBytes":"100-1000","sessionIDPlacement":"query","sessionPlacement":"query"}`),
	}
}

func TestXRayStartsWithoutLocalInbounds(t *testing.T) {
	cfg, err := buildConfig(fixtureOptions())
	if err != nil {
		t.Fatal(err)
	}
	instance, err := X.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
}

func TestXHttpConfigFrom3xUI(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up", "auto"} {
		t.Run(mode, func(t *testing.T) {
			profile := fixtureOptions()
			profile.Mode = mode
			if _, err := buildConfig(profile); err != nil {
				t.Fatal(err)
			}
			transport, err := transportSettings(profile)
			if err != nil {
				t.Fatal(err)
			}
			if string(transport["mode"]) != `"`+mode+`"` || transport["sessionPlacement"] != nil ||
				string(transport["sessionIDPlacement"]) != `"query"` {
				t.Fatalf("incorrect mode or alias normalization")
			}
		})
	}
}

func TestXHttpRejectsUnsupportedSettings(t *testing.T) {
	cases := []struct {
		message string
		edit    func(*Options)
	}{
		{"flow", func(p *Options) { p.Flow = "xtls-rprx-vision" }},
		{"encryption", func(p *Options) { p.Encryption = "mlkem768x25519plus" }},
		{"downloadSettings", func(p *Options) { p.Extra = json.RawMessage(`{"downloadSettings":{"address":"other.example"}}`) }},
		{"ALPN h3", func(p *Options) { p.Security = "tls"; p.ALPN = []string{"h3"} }},
	}
	for _, test := range cases {
		t.Run(test.message, func(t *testing.T) {
			profile := fixtureOptions()
			test.edit(&profile)
			if _, err := buildConfig(profile); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected an error mentioning %q, got %v", test.message, err)
			}
		})
	}
}
