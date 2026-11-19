package xhttp

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	XN "github.com/xtls/xray-core/common/net"
	X "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
)

type xhttpOutbound struct {
	outbound.Adapter
	config *X.Config
	dialer N.Dialer
	server M.Socksaddr
	active atomic.Pointer[xrayInstance]
}

type xrayInstance struct {
	core   *X.Instance
	ctx    context.Context
	dialer N.Dialer
	server M.Socksaddr
}

type instanceKey struct{}
type systemDialer struct{}

// Xray's dialer is global. The request context holds the owning outbound,
// including its private lifecycle and the server selected by sing-box.
var installSystemDialer sync.Once

func (systemDialer) DestIpAddress() XN.IP { return nil }

func (systemDialer) Dial(ctx context.Context, _ XN.Address, dest XN.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	instance, _ := ctx.Value(instanceKey{}).(*xrayInstance)
	if instance == nil || dest.Network != XN.Network_TCP ||
		dest.NetAddr() != instance.server.String() {
		return nil, errors.New("XHTTP: неожиданный адрес подключения Xray")
	}
	if err := instance.ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := instance.dialer.DialContext(ctx, N.NetworkTCP, instance.server)
	if err != nil {
		return nil, err
	}
	return &managedConn{Conn: conn, stop: context.AfterFunc(instance.ctx, func() { _ = conn.Close() })}, nil
}

type managedConn struct {
	net.Conn
	stop   func() bool
	cancel context.CancelFunc
}

func (c *managedConn) Close() error {
	c.stop()
	if c.cancel != nil {
		c.cancel()
	}
	return c.Conn.Close()
}

func Register(registry *outbound.Registry) {
	outbound.Register[Options](registry, Type, newOutbound)
}

func newOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	config, err := buildConfig(options)
	if err != nil {
		return nil, err
	}
	serverDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	return &xhttpOutbound{
		Adapter: outbound.NewAdapterWithDialerOptions(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		config:  config, dialer: serverDialer, server: options.ServerOptions.Build(),
	}, nil
}

func (p *xhttpOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := dialer.InitializeDetour(p.dialer); err != nil {
		return err
	}
	installSystemDialer.Do(func() { internet.UseAlternativeSystemDialer(systemDialer{}) })
	instance := &xrayInstance{ctx: scope.Context(), dialer: p.dialer, server: p.server}
	core, err := X.NewWithContext(instance.ctx, p.config)
	if err != nil {
		return err
	}
	if err = core.Start(); err != nil {
		_ = core.Close()
		return err
	}
	instance.core = core
	p.active.Store(instance)
	scope.Add(func() error {
		p.active.Store(nil)
		return core.Close()
	})
	return nil
}

func (p *xhttpOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP && network != N.NetworkUDP {
		return nil, errors.New("XHTTP: неподдерживаемая сеть")
	}
	instance := p.active.Load()
	if instance == nil {
		return nil, net.ErrClosed
	}
	dest, err := XN.ParseDestination(network + ":" + destination.String())
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Xray dispatches asynchronously. DNS pools cancel the dial context as
	// soon as they get the virtual connection.
	connCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(instance.ctx, cancel)
	connCtx = context.WithValue(connCtx, instanceKey{}, instance)
	conn, err := X.Dial(connCtx, instance.core, dest)
	if err != nil {
		stop()
		cancel()
		return nil, err
	}
	wrapped := &managedConn{Conn: conn, stop: stop, cancel: cancel}
	if err := ctx.Err(); err != nil {
		_ = wrapped.Close()
		return nil, err
	}
	return wrapped, nil
}

func (p *xhttpOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := p.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return bufio.NewUnbindPacketConnWithAddr(conn, destination), nil
}
