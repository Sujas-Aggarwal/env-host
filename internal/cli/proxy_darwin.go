//go:build darwin

package cli

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"env-host/internal/policy"
)

type policyProxy struct {
	rules    policy.Policy
	token    string
	port     int
	server   *http.Server
	listener net.Listener
}

func startPolicyProxy(rules policy.Policy) (*policyProxy, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("cannot start policy proxy: %w", err)
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		listener.Close()
		return nil, err
	}
	proxy := &policyProxy{rules: rules, token: hex.EncodeToString(secret), listener: listener,
		port: listener.Addr().(*net.TCPAddr).Port}
	clear(secret)
	proxy.server = &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	go proxy.server.Serve(listener)
	return proxy, nil
}

func (p *policyProxy) Close() { p.server.Close() }

func (p *policyProxy) URL() string {
	return fmt.Sprintf("http://envh:%s@127.0.0.1:%d", p.token, p.port)
}

func (p *policyProxy) authorized(r *http.Request) bool {
	parts := strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(decoded, []byte("envh:"+p.token)) == 1
}

func proxyTarget(r *http.Request) (string, string, error) {
	var host, port string
	if r.Method == http.MethodConnect {
		var err error
		host, port, err = net.SplitHostPort(r.Host)
		if err != nil {
			return "", "", fmt.Errorf("CONNECT needs host:port")
		}
	} else {
		if r.URL == nil || !r.URL.IsAbs() || !strings.EqualFold(r.URL.Scheme, "http") || r.URL.User != nil {
			return "", "", fmt.Errorf("expected an absolute HTTP proxy request")
		}
		host, port = r.URL.Hostname(), r.URL.Port()
		if port == "" {
			port = "80"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strings.Contains(host, "*") {
		return "", "", fmt.Errorf("invalid proxy destination")
	}
	host, err = policy.NormalizeHost(host)
	if err != nil {
		return "", "", err
	}
	return host, strconv.Itoa(n), nil
}

func privateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// resolve once and dial the chosen numeric address so DNS cannot change between
// the policy decision and the connection.
func (p *policyProxy) dial(ctx context.Context, host, port string, explicit bool) (net.Conn, error) {
	var ips []net.IP
	literal := net.ParseIP(host) != nil
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		found, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, item := range found {
			ips = append(ips, item.IP)
		}
	}
	var last error = fmt.Errorf("no permitted address for %s", host)
	for _, ip := range ips {
		if privateIP(ip) && (!literal || !explicit) {
			continue
		}
		if ip.IsUnspecified() || ip.IsMulticast() || (ip.IsLoopback() && port == strconv.Itoa(p.port)) {
			continue
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

func (p *policyProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.authorized(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="envh"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	host, port, err := proxyTarget(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	allowed, explicit := p.rules.Decide(host, port)
	if !allowed {
		http.Error(w, "blocked by envh policy", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r, host, port, explicit)
		return
	}
	p.forward(w, r, host, port, explicit)
}

func (p *policyProxy) connect(w http.ResponseWriter, r *http.Request, host, port string, explicit bool) {
	upstream, err := p.dial(r.Context(), host, port, explicit)
	if err != nil {
		http.Error(w, "cannot connect to permitted destination", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "proxy tunnel unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffered.Flush(); err != nil {
		return
	}
	go func() {
		io.Copy(upstream, buffered.Reader)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()
	io.Copy(client, upstream)
}

func (p *policyProxy) forward(w http.ResponseWriter, r *http.Request, host, port string, explicit bool) {
	request := r.Clone(r.Context())
	request.RequestURI = ""
	request.Host = net.JoinHostPort(host, port)
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	request.Header.Del("Connection")
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return p.dial(ctx, host, port, explicit)
	}}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(request)
	if err != nil {
		http.Error(w, "cannot reach permitted destination", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}
