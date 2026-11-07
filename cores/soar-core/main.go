// soar-core: the Soar core of Last Net.
//
// A local SOCKS5 (CONNECT only) proxy whose connections travel through a Soar DNS tunnel
// (github.com/getlantern/soar, Apache-2.0). It is the Soar counterpart of the dnstt / vaydns /
// slipstream cores: Last Net starts it as a child process, waits for its loopback port, and talks
// SOCKS5 to that port exactly as it does for a SOCKS server behind the other tunnels.
//
//	soar-core -zone t.example.com -pubkey BASE64 -resolver 8.8.8.8,1.1.1.1 -listen 127.0.0.1:1836
//
// With -forward host:port the proxy does not speak SOCKS5 at all: every connection is piped, as raw TCP, to that
// destination through the tunnel. That is what an SSH login behind Soar needs (the SSH client talks straight to
// the port; the Soar server dials its own sshd).
//
// What it does NOT do on purpose:
//   - listen on anything but loopback (the proxy has no login; whoever can reach it can use the tunnel);
//   - UDP ASSOCIATE or BIND (Soar carries TCP streams only);
//   - look up host names for its resolvers (they must be IP addresses, so it never needs system DNS).
//
// The Soar server decides where a connection may go (by default public addresses on ports 80 and 443).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/getlantern/soar"
)

// version is set at build time: -ldflags "-X main.version=...".
var version = "dev"

// probeTarget is the destination of the throw-away stream that proves the tunnel is up. Opening a stream returns only
// after the server has authenticated itself, so it is a real round trip whenever a session has to be (re)established.
const probeTarget = "1.1.1.1:443"

// probeWait is how long a SOCKS greeting waits for that proof before the connection is dropped unanswered.
const probeWait = 10 * time.Second

// tunnel is the Soar client plus what the SOCKS side needs from it: dialling, and a liveness check.
type tunnel struct {
	c        *soar.Client
	mu       sync.Mutex
	lastGood time.Time
}

func (t *tunnel) touch() {
	t.mu.Lock()
	t.lastGood = time.Now()
	t.mu.Unlock()
}

// fresh reports whether the tunnel carried something a moment ago.
func (t *tunnel) fresh() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.lastGood.IsZero() && time.Since(t.lastGood) < 5*time.Second
}

// dial opens a stream to addr through the tunnel, waiting at most wait for the session.
func (t *tunnel) dial(ctx context.Context, addr string, wait time.Duration) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	conn, err := t.c.DialContext(dctx, "tcp", addr)
	if err == nil {
		t.touch()
	}
	return conn, err
}

// alive makes sure a session with the server exists (handshaking if needed) by opening and closing one stream.
// A tunnel that carried something in the last few seconds is taken as alive without asking again.
func (t *tunnel) alive(ctx context.Context, wait time.Duration) error {
	if t.fresh() {
		return nil
	}
	conn, err := t.dial(ctx, probeTarget, wait)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// SOCKS5 reply codes (RFC 1928).
const (
	repSucceeded       = 0x00
	repGeneralFailure  = 0x01
	repHostUnreachable = 0x04
	repCommandNotSupp  = 0x07
	repAddrNotSupp     = 0x08
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "soar-core: error:", err)
		os.Exit(1)
	}
}

// listFlag is a flag that may be repeated and/or comma-separated.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func run() error {
	var (
		zone      = flag.String("zone", "", "tunnel zone (the delegated domain), e.g. t.example.com")
		pubkey    = flag.String("pubkey", "", "server Ed25519 public key (base64 or hex)")
		listen    = flag.String("listen", "127.0.0.1:10886", "local SOCKS5 listen address (loopback only)")
		tcpMode   = flag.String("tcp", "auto", "TCP/53 paths: auto | on | only | off")
		discovery = flag.Bool("discovery", false, "also discover resolvers that carry the tunnel")
		country   = flag.String("country", "", "country code for the discovery lists, e.g. IR")
		dialWait  = flag.Duration("dial-timeout", 30*time.Second, "how long a SOCKS CONNECT waits for the tunnel")
		forward   = flag.String("forward", "", "host:port: pipe every connection there through the tunnel instead of speaking SOCKS5")
		verbose   = flag.Bool("v", false, "debug log")
		showVer   = flag.Bool("version", false, "print the version and exit")
		resolvers listFlag
	)
	flag.Var(&resolvers, "resolver", "recursive resolver IP[:port]; repeat the flag or comma-separate")
	flag.Parse()

	if *showVer {
		fmt.Println("soar-core", version)
		return nil
	}

	zoneName := strings.TrimSpace(*zone)
	if zoneName == "" {
		return errors.New("-zone is required")
	}
	key, err := parseKey(*pubkey)
	if err != nil {
		return err
	}
	switch *tcpMode {
	case "auto", "on", "only", "off":
	default:
		return fmt.Errorf("-tcp must be auto, on, only or off, not %q", *tcpMode)
	}
	var rs []string
	seen := map[string]bool{}
	for _, r := range resolvers {
		n, err := normResolver(r)
		if err != nil {
			return err
		}
		if !seen[n] {
			seen[n] = true
			rs = append(rs, n)
		}
	}
	if len(rs) == 0 && !*discovery {
		return errors.New("give at least one -resolver, or turn -discovery on")
	}
	if err := checkLoopback(*listen); err != nil {
		return err
	}
	fwd := strings.TrimSpace(*forward)
	if fwd != "" {
		h, p, err := net.SplitHostPort(fwd)
		if err != nil || h == "" {
			return fmt.Errorf("-forward must be host:port, not %q", fwd)
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("-forward: bad port in %q", fwd)
		}
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level, ReplaceAttr: dropTime}))

	client, err := soar.NewClient(soar.Config{
		Zone:      zoneName,
		ServerKey: key,
		Resolvers: rs,
		Discovery: soar.Discovery{Enabled: *discovery, Country: strings.ToUpper(strings.TrimSpace(*country))},
		TCP:       *tcpMode,
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("soar: %w", err)
	}
	defer client.Close()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", *listen, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	logger.Info("soar-core listening",
		"addr", ln.Addr().String(), "zone", zoneName, "resolvers", len(rs),
		"tcp", *tcpMode, "discovery", *discovery, "forward", fwd, "version", version)

	// The handshake is lazy: start it now, so "tunnel ready" shows up in the log as soon as the zone, the key and a
	// resolver agree, and the first real connection does not pay for it.
	tun := &tunnel{c: client}
	go warmUp(ctx, tun, logger)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			logger.Error("accept failed", "err", err.Error())
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if fwd != "" {
			go serveForward(ctx, conn, tun, fwd, *dialWait, logger)
		} else {
			go serve(ctx, conn, tun, *dialWait, logger)
		}
	}
}

func dropTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

// warmUp opens (and at once closes) one stream so the session handshake happens, retrying with a growing pause
// until it works. Success means the zone, the key and at least one resolver are right.
func warmUp(ctx context.Context, t *tunnel, log *slog.Logger) {
	delay := time.Second
	for attempt := 1; ; attempt++ {
		start := time.Now()
		err := t.alive(ctx, 12*time.Second)
		if err == nil {
			log.Info("soar: tunnel ready (authenticated session)",
				"attempt", attempt, "took", time.Since(start).Round(time.Millisecond).String())
			return
		}
		if ctx.Err() != nil {
			return
		}
		log.Warn("soar: tunnel not ready yet", "attempt", attempt, "err", err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < 5*time.Second {
			delay += time.Second
		}
	}
}

// serveForward pipes one connection to the fixed destination through the tunnel (see -forward).
func serveForward(ctx context.Context, conn net.Conn, t *tunnel, target string, dialWait time.Duration, log *slog.Logger) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Error("panic in a connection handler", "panic", fmt.Sprint(r))
		}
	}()
	start := time.Now()
	up, err := t.dial(ctx, target, dialWait)
	if err != nil {
		log.Debug("tunnel dial failed", "target", target, "err", err.Error())
		return
	}
	defer up.Close()
	log.Debug("stream open", "target", target, "dial", time.Since(start).Round(time.Millisecond).String())
	sent, got := pipe(conn, up)
	log.Debug("stream closed", "target", target, "sent", sent, "received", got,
		"lasted", time.Since(start).Round(time.Millisecond).String())
}

// serve handles one SOCKS5 client.
func serve(ctx context.Context, conn net.Conn, t *tunnel, dialWait time.Duration, log *slog.Logger) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Error("panic in a connection handler", "panic", fmt.Sprint(r))
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	// The greeting is answered only when the tunnel is up: Last Net's own "is the tunnel alive" check is a SOCKS
	// greeting, so it must fail while the tunnel is down instead of being answered by this local proxy alone.
	if err := socksNegotiate(conn, func() error { return t.alive(ctx, probeWait) }); err != nil {
		log.Debug("socks greeting failed", "err", err.Error())
		return
	}
	host, port, err := socksRequest(conn)
	if err != nil {
		log.Debug("socks request failed", "err", err.Error())
		return
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// The deadline now has to cover the wait for the tunnel plus the reply.
	_ = conn.SetDeadline(time.Now().Add(dialWait + 10*time.Second))
	up, err := t.dial(ctx, addr, dialWait)
	if err != nil {
		log.Debug("tunnel dial failed", "target", addr, "err", err.Error())
		_ = socksReply(conn, repHostUnreachable)
		return
	}
	defer up.Close()

	if err := socksReply(conn, repSucceeded); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	opened := time.Now()
	sent, got := pipe(conn, up)
	log.Debug("stream closed", "target", addr, "sent", sent, "received", got,
		"lasted", time.Since(opened).Round(time.Millisecond).String())
}

// socksNegotiate answers the method selection. "No authentication" is preferred; a client that only offers
// username/password gets it accepted with any login (the listener is loopback-only). ready runs before the answer:
// when it fails the connection is dropped without one.
func socksNegotiate(conn net.Conn, ready func() error) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 5 {
		return fmt.Errorf("not SOCKS5 (version byte %d)", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	var noAuth, userPass bool
	for _, m := range methods {
		switch m {
		case 0:
			noAuth = true
		case 2:
			userPass = true
		}
	}
	if !noAuth && !userPass {
		_, _ = conn.Write([]byte{5, 0xFF})
		return errors.New("no acceptable SOCKS5 method offered")
	}
	if err := ready(); err != nil {
		return fmt.Errorf("tunnel not ready: %w", err)
	}
	if noAuth {
		_, err := conn.Write([]byte{5, 0})
		return err
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return err
	}
	return readUserPass(conn)
}

// readUserPass reads an RFC 1929 login and accepts it.
func readUserPass(conn net.Conn) error {
	var v [1]byte
	if _, err := io.ReadFull(conn, v[:]); err != nil {
		return err
	}
	if v[0] != 1 {
		return fmt.Errorf("bad username/password version %d", v[0])
	}
	for i := 0; i < 2; i++ { // username, then password
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		if _, err := io.CopyN(io.Discard, conn, int64(l[0])); err != nil {
			return err
		}
	}
	_, err := conn.Write([]byte{1, 0})
	return err
}

// socksRequest reads a CONNECT request and returns its target. For anything else it answers the client itself.
func socksRequest(conn net.Conn) (string, int, error) {
	var h [4]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return "", 0, err
	}
	if h[0] != 5 {
		return "", 0, fmt.Errorf("bad SOCKS5 request version %d", h[0])
	}
	if h[1] != 1 {
		_ = socksReply(conn, repCommandNotSupp)
		return "", 0, fmt.Errorf("SOCKS5 command %d is not supported (CONNECT only)", h[1])
	}
	var host string
	switch h[3] {
	case 1: // IPv4
		var b [4]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(b[:]).String()
	case 3: // domain name
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			_ = socksReply(conn, repAddrNotSupp)
			return "", 0, errors.New("empty host name in SOCKS5 request")
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	case 4: // IPv6
		var b [16]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(b[:]).String()
	default:
		_ = socksReply(conn, repAddrNotSupp)
		return "", 0, fmt.Errorf("unknown SOCKS5 address type %d", h[3])
	}
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		return "", 0, err
	}
	port := int(p[0])<<8 | int(p[1])
	if port == 0 {
		_ = socksReply(conn, repGeneralFailure)
		return "", 0, errors.New("SOCKS5 request for port 0")
	}
	return host, port, nil
}

// socksReply sends a reply with a zero bind address.
func socksReply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

type closeWriter interface{ CloseWrite() error }

// pipe copies both ways until both directions end and returns how many bytes went a->b and b->a. When one
// direction ends the other gets 15 seconds to finish (half-closed connections are normal), then both sides are
// closed so nothing lingers.
func pipe(a, b net.Conn) (toB, toA int64) {
	done := make(chan struct{}, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	go func() {
		toB, _ = io.Copy(b, a)
		if cw, ok := b.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		toA, _ = io.Copy(a, b)
		if cw, ok := a.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	t := time.AfterFunc(15*time.Second, closeBoth)
	<-done
	t.Stop()
	closeBoth()
	return toB, toA
}

// parseKey reads the server's Ed25519 public key: 32 bytes as base64 (any variant) or as 64 hex characters.
func parseKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("-pubkey is required")
	}
	if len(s) == 2*ed25519.PublicKeySize {
		if b, err := hex.DecodeString(s); err == nil {
			return ed25519.PublicKey(b), nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, errors.New("-pubkey must be a 32-byte Ed25519 public key as base64 or hex")
}

// normResolver turns "8.8.8.8", "8.8.8.8:53", "2001:db8::1" or "[2001:db8::1]:53" into host:port. A resolver must
// be an IP address: a name would need the system resolver, which is exactly what a censored network breaks.
func normResolver(r string) (string, error) {
	r = strings.TrimSpace(r)
	if r == "" {
		return "", errors.New("empty resolver")
	}
	if h, p, err := net.SplitHostPort(r); err == nil {
		if net.ParseIP(h) == nil {
			return "", fmt.Errorf("resolver %q: the host must be an IP address", r)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("resolver %q: bad port", r)
		}
		return net.JoinHostPort(h, strconv.Itoa(n)), nil
	}
	bare := strings.Trim(r, "[]")
	if net.ParseIP(bare) == nil {
		return "", fmt.Errorf("resolver %q is not an IP address (use 8.8.8.8 or 8.8.8.8:53)", r)
	}
	return net.JoinHostPort(bare, "53"), nil
}

// checkLoopback refuses a listen address another machine could reach.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("bad -listen %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("-listen must be a loopback address (127.0.0.1 or ::1), not %q: the proxy has no login, so anyone who could reach it could use your tunnel", host)
}
