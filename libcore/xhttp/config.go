package xhttp

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/option"
	X "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

const Type = "xray-xhttp"

type Options struct {
	option.DialerOptions
	option.ServerOptions
	UUID          string          `json:"uuid"`
	Flow          string          `json:"flow,omitempty"`
	Encryption    string          `json:"encryption,omitempty"`
	Host          string          `json:"host,omitempty"`
	Path          string          `json:"path,omitempty"`
	Mode          string          `json:"mode,omitempty"`
	Extra         json.RawMessage `json:"extra,omitempty"`
	Security      string          `json:"security,omitempty"`
	ServerName    string          `json:"server_name,omitempty"`
	ALPN          []string        `json:"alpn,omitempty"`
	Fingerprint   string          `json:"fingerprint,omitempty"`
	PublicKey     string          `json:"public_key,omitempty"`
	ShortID       string          `json:"short_id,omitempty"`
	SpiderX       string          `json:"spider_x,omitempty"`
	MLDSAVerify   string          `json:"mldsa65_verify,omitempty"`
	AllowInsecure bool            `json:"allow_insecure,omitempty"`
	Certificate   string          `json:"certificate,omitempty"`
	ECH           bool            `json:"ech,omitempty"`
}

type fields = map[string]any

func buildConfig(options Options) (*X.Config, error) {
	if !options.ServerOptions.Build().IsValid() || options.ServerPort == 0 || options.UUID == "" {
		return nil, errors.New("XHTTP: укажите адрес, порт и идентификатор VLESS")
	}
	if options.Flow != "" && options.Flow != "auto" {
		return nil, errors.New("XHTTP: для этого транспорта требуется пустой VLESS flow")
	}
	if options.Encryption != "" && options.Encryption != "none" {
		return nil, errors.New("XHTTP: поддерживается VLESS encryption=none")
	}
	if options.ECH || options.AllowInsecure {
		return nil, errors.New("XHTTP: ECH и отключение проверки TLS не поддерживаются")
	}
	security := options.Security
	if security == "" {
		security = "none"
	}
	transport, err := transportSettings(options)
	if err != nil {
		return nil, err
	}
	stream := fields{"network": "xhttp", "xhttpSettings": transport, "security": security}
	switch security {
	case "none":
	case "reality":
		if options.PublicKey == "" {
			return nil, errors.New("XHTTP: отсутствует открытый ключ REALITY")
		}
		fingerprint := options.Fingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		stream["realitySettings"] = fields{
			"serverName": options.ServerName, "fingerprint": fingerprint, "password": options.PublicKey,
			"shortId": options.ShortID, "spiderX": options.SpiderX, "mldsa65Verify": options.MLDSAVerify,
		}
	case "tls":
		if slices.Contains(options.ALPN, "h3") {
			return nil, errors.New("XHTTP: ALPN h3 пока не поддерживается")
		}
		fingerprint := options.Fingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		tls := fields{"serverName": options.ServerName, "alpn": options.ALPN, "fingerprint": fingerprint}
		if options.Certificate != "" {
			tls["certificates"] = []fields{{"usage": "verify", "certificate": strings.Split(options.Certificate, "\n")}}
		}
		stream["tlsSettings"] = tls
	default:
		return nil, errors.New("XHTTP: неизвестный режим защиты")
	}
	raw, err := json.Marshal(fields{
		"log": fields{"loglevel": "none"},
		"outbounds": []fields{{
			"protocol": "vless",
			"settings": fields{"vnext": []fields{{
				"address": options.Server, "port": options.ServerPort,
				"users": []fields{{"id": options.UUID, "encryption": "none"}},
			}}},
			"streamSettings": stream,
		}},
	})
	if err != nil {
		return nil, err
	}
	var cfg conf.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, errors.New("XHTTP: неверный тип значения в параметрах транспорта")
	}
	built, err := cfg.Build()
	if err != nil {
		return nil, errors.New("XHTTP: Xray отклонил параметры транспорта или защиты")
	}
	return built, nil
}

func transportSettings(options Options) (map[string]json.RawMessage, error) {
	transport := make(map[string]json.RawMessage)
	if len(options.Extra) > 32768 {
		return nil, errors.New("XHTTP: слишком большой extra")
	}
	if len(options.Extra) > 0 && (json.Unmarshal(options.Extra, &transport) != nil || transport == nil) {
		return nil, errors.New("XHTTP: extra должен быть объектом JSON")
	}
	for key := range transport {
		switch key {
		case "host", "path", "mode", "headers", "xPaddingBytes", "xPaddingObfsMode",
			"xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod", "uplinkHTTPMethod",
			"sessionIDPlacement", "sessionIDKey", "sessionIDTable", "sessionIDLength",
			"sessionPlacement", "sessionKey", "seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey",
			"uplinkChunkSize", "noGRPCHeader", "scMaxEachPostBytes", "scMinPostsIntervalMs", "xmux":
		case "downloadSettings":
			return nil, errors.New("XHTTP: отдельное подключение downloadSettings пока не поддерживается")
		default:
			return nil, errors.New("XHTTP: в extra есть неподдерживаемое поле")
		}
	}
	for alias, canonical := range map[string]string{"sessionPlacement": "sessionIDPlacement", "sessionKey": "sessionIDKey"} {
		if legacy := transport[alias]; legacy != nil {
			if transport[canonical] == nil {
				transport[canonical] = legacy
			}
			delete(transport, alias)
		}
	}
	for key, value := range map[string]string{"host": options.Host, "path": options.Path, "mode": options.Mode} {
		if value != "" {
			transport[key], _ = json.Marshal(value)
		}
	}
	return transport, nil
}
