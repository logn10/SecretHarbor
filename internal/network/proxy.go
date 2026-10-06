package network

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/secretharbor/secretharbor/internal/broker"
	"github.com/secretharbor/secretharbor/internal/policy"
)

var privateIPBlocks []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"127.0.0.0/8",    // IPv4 Loopback
		"169.254.0.0/16", // IPv4 Link-local
		"::1/128",        // IPv6 Loopback
		"fc00::/7",       // IPv6 Unique Local
		"fe80::/10",      // IPv6 Link-local
	}
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err == nil {
			privateIPBlocks = append(privateIPBlocks, block)
		}
	}
}

// isPrivateOrLoopbackIP checks all RFC1918, loopback, and link-local ranges (BUG-032).
func isPrivateOrLoopbackIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ForwardProxy is an HTTP/HTTPS forward proxy that filters outbound agent requests by domain
// and dynamically injects real secrets into authorized HTTPS connections.
type ForwardProxy struct {
	listener       net.Listener
	port           int
	mode           policy.NetworkMode
	allowedDomains map[string]bool
	deniedDomains  map[string]bool
	forbidPrivate  bool
	sessionToken   string
	broker         *broker.Broker
	ca             *CertificateAuthority
	mu             sync.RWMutex
	server         *http.Server
}

// StartForwardProxy starts a local filtering proxy bound to 127.0.0.1 on an ephemeral port.
func StartForwardProxy(mode policy.NetworkMode, allowedDomains []string, deniedDomains ...[]string) (*ForwardProxy, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind local network proxy: %w", err)
	}

	ca, err := NewCertificateAuthority()
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("failed to initialize proxy Root CA: %w", err)
	}

	fp := &ForwardProxy{
		listener:       l,
		port:           l.Addr().(*net.TCPAddr).Port,
		mode:           mode,
		allowedDomains: make(map[string]bool),
		deniedDomains:  make(map[string]bool),
		sessionToken:   os.Getenv("SECRETHARBOR_PROXY_TOKEN"),
		forbidPrivate:  os.Getenv("SECRETHARBOR_FORBID_PRIVATE_IP") == "1",
		ca:             ca,
	}

	for _, d := range allowedDomains {
		fp.allowedDomains[strings.ToLower(strings.TrimSpace(d))] = true
	}
	if len(deniedDomains) > 0 {
		for _, d := range deniedDomains[0] {
			dLower := strings.ToLower(strings.TrimSpace(d))
			fp.deniedDomains[dLower] = true
			if dLower == "private" || dLower == "rfc1918" || dLower == "127.0.0.1" || dLower == "10.0.0.0/8" || dLower == "192.168.0.0/16" {
				fp.forbidPrivate = true
			}
		}
	}

	fp.server = &http.Server{
		Handler:      fp,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		_ = fp.server.Serve(l)
	}()

	return fp, nil
}

// SetSessionToken configures an expected session authorization token for proxy connections (BUG-039).
func (fp *ForwardProxy) SetSessionToken(token string) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.sessionToken = token
}

// SessionToken returns the active session authentication token.
func (fp *ForwardProxy) SessionToken() string {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	return fp.sessionToken
}

// SetForbidPrivateIP explicitly toggles private IP egress enforcement.
func (fp *ForwardProxy) SetForbidPrivateIP(forbid bool) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.forbidPrivate = forbid
}

// Port returns the listening TCP port of the proxy.
func (fp *ForwardProxy) Port() int {
	return fp.port
}

// ProxyURL returns the HTTP URL of the local proxy.
func (fp *ForwardProxy) ProxyURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", fp.port)
}

// CACertPath returns the path to the temporary Root CA certificate.
func (fp *ForwardProxy) CACertPath() string {
	if fp.ca != nil {
		return fp.ca.CertPath()
	}
	return ""
}

// SetBroker attaches a secret broker for transparent credential injection.
func (fp *ForwardProxy) SetBroker(b *broker.Broker) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.broker = b
}

// Close terminates the proxy server and cleans up certificates.
func (fp *ForwardProxy) Close() error {
	if fp.ca != nil {
		fp.ca.Cleanup()
	}
	if fp.server != nil {
		return fp.server.Close()
	}
	return nil
}

// ServeHTTP handles both standard HTTP requests and HTTPS CONNECT tunnels.
func (fp *ForwardProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Authentication or session token check on proxy connections (BUG-039)
	fp.mu.RLock()
	token := fp.sessionToken
	fp.mu.RUnlock()
	if token != "" {
		authHdr := req.Header.Get("Proxy-Authorization")
		customHdr := req.Header.Get("X-SecretHarbor-Token")
		valid := false
		if customHdr != "" && subtle.ConstantTimeCompare([]byte(customHdr), []byte(token)) == 1 {
			valid = true
		} else if authHdr != "" {
			trimmed := strings.TrimPrefix(authHdr, "Bearer ")
			trimmed = strings.TrimPrefix(trimmed, "Basic ")
			trimmed = strings.TrimSpace(trimmed)
			if subtle.ConstantTimeCompare([]byte(trimmed), []byte(token)) == 1 {
				valid = true
			}
		}
		if !valid {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"SecretHarbor\"")
			http.Error(w, "SecretHarbor: Proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
	}

	if fp.mode == policy.NetworkModeDeny {
		http.Error(w, "SecretHarbor: All outbound network access denied by strict policy", http.StatusForbidden)
		return
	}

	host := extractHost(req)

	// Explicit domain denial check (applies to both allow and restricted modes)
	if fp.isHostDenied(host) {
		http.Error(w, fmt.Sprintf("SecretHarbor: Access to host %q explicitly denied by network policy", host), http.StatusForbidden)
		return
	}

	// In allow mode, do not skip private IP checks when policy forbids private IP egress (BUG-032)
	if fp.mode == policy.NetworkModeAllow {
		if fp.isPrivateIPEgressForbidden(host) {
			http.Error(w, fmt.Sprintf("SecretHarbor: Access to private host %q forbidden by network policy", host), http.StatusForbidden)
			return
		}

		if req.Method == http.MethodConnect {
			fp.handleConnect(w, req)
		} else {
			fp.handleHTTP(w, req)
		}
		return
	}

	// Restricted Mode: verify target host
	if !fp.isHostAllowed(host) {
		http.Error(w, fmt.Sprintf("SecretHarbor: Access to host %q denied by network policy", host), http.StatusForbidden)
		return
	}

	if req.Method == http.MethodConnect {
		fp.handleConnect(w, req)
	} else {
		fp.handleHTTP(w, req)
	}
}

func (fp *ForwardProxy) isPrivateIPEgressForbidden(host string) bool {
	fp.mu.RLock()
	defer fp.mu.RUnlock()

	if !fp.forbidPrivate {
		return false
	}

	// If explicitly allowed in allowedDomains, permit
	if fp.allowedDomains[host] {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		return isPrivateOrLoopbackIP(ip)
	}

	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}

	return false
}

func (fp *ForwardProxy) isHostDenied(host string) bool {
	host = strings.ToLower(host)

	fp.mu.RLock()
	defer fp.mu.RUnlock()

	if fp.deniedDomains[host] {
		return true
	}

	for denied := range fp.deniedDomains {
		if strings.HasSuffix(host, "."+denied) {
			return true
		}
		// Match CIDR deny blocks (BUG-032)
		if _, cidr, err := net.ParseCIDR(denied); err == nil {
			if ip := net.ParseIP(host); ip != nil && cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
}

func (fp *ForwardProxy) isHostAllowed(host string) bool {
	host = strings.ToLower(host)

	// Block loopback / private IP by default unless explicitly allowed (BUG-032)
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateOrLoopbackIP(ip) && !fp.allowedDomains[host] {
			return false
		}
	}
	if (host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0") && !fp.allowedDomains[host] {
		return false
	}

	fp.mu.RLock()
	defer fp.mu.RUnlock()

	if fp.allowedDomains[host] {
		return true
	}

	// Check domain wildcards (e.g. allowed: github.com also matches api.github.com)
	for allowed := range fp.allowedDomains {
		if strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}

	return false
}

func (fp *ForwardProxy) checkDNSRebinding(host string) bool {
	// If domain is explicitly allowed or literal localhost, skip DNS rebinding check
	fp.mu.RLock()
	allowed := fp.allowedDomains[host]
	fp.mu.RUnlock()
	if allowed || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return false
	}

	// Check resolved IPs against all RFC1918, loopback, and link-local ranges (BUG-032)
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if isPrivateOrLoopbackIP(ip) {
				return true // Rebinding detected
			}
		}
	}
	return false
}

func (fp *ForwardProxy) handleConnect(w http.ResponseWriter, req *http.Request) {
	host := extractHost(req)

	// DNS Rebinding check: verify resolved IP is not loopback/private RFC1918 (BUG-032)
	if fp.checkDNSRebinding(host) {
		http.Error(w, "SecretHarbor: DNS rebinding to loopback/private IP prohibited", http.StatusForbidden)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Check if this host has registered capabilities for secret injection
	fp.mu.RLock()
	b := fp.broker
	hasCap := b != nil && b.HasCapabilityForHost(host)
	fp.mu.RUnlock()

	if hasCap && fp.ca != nil {
		// Respond 200 Connection Established to client
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}

		// Perform TLS Handshake with client using dynamic certificate
		cert, err := fp.ca.GetHostCertificate(host)
		if err != nil {
			return
		}

		// Explicitly set MinVersion: tls.VersionTLS12 (BUG-039)
		tlsClient := tls.Server(clientConn, &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		})
		defer tlsClient.Close()

		// Set deadline on client TLS handshake to prevent hung connections
		_ = clientConn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsClient.Handshake(); err != nil {
			return
		}
		_ = clientConn.SetDeadline(time.Time{})

		// Handle keep-alive loop and explicitly signal Connection: close when done (BUG-032)
		reader := bufio.NewReader(tlsClient)
		targetAddr := req.Host
		if _, _, err := net.SplitHostPort(targetAddr); err != nil {
			targetAddr = net.JoinHostPort(strings.Trim(targetAddr, "[]"), "443")
		}

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12, // BUG-039
		}
		if net.ParseIP(host) == nil {
			tlsConfig.ServerName = host
		}
		dialer := &net.Dialer{
			Timeout: 10 * time.Second,
		}

		for {
			interceptedReq, err := http.ReadRequest(reader)
			if err != nil {
				return
			}

			// Inject real secrets at boundary
			b.InterceptAndInject(interceptedReq)

			tlsUpstream, err := tls.DialWithDialer(dialer, "tcp", targetAddr, tlsConfig)
			if err != nil {
				return
			}

			// Ensure clean closure per request to avoid keep-alive mismatch (BUG-032)
			interceptedReq.Header.Set("Connection", "close")
			interceptedReq.Close = true

			if err := interceptedReq.Write(tlsUpstream); err != nil {
				_ = tlsUpstream.Close()
				return
			}

			upstreamResp, err := http.ReadResponse(bufio.NewReader(tlsUpstream), interceptedReq)
			if err != nil {
				_ = tlsUpstream.Close()
				return
			}

			// Send Connection: close so keep-alive clients do not break (BUG-032)
			upstreamResp.Header.Set("Connection", "close")
			upstreamResp.Close = true

			_ = upstreamResp.Write(tlsClient)
			_ = upstreamResp.Body.Close()
			_ = tlsUpstream.Close()
			return
		}
	}

	// Standard transparent TCP tunnel for destinations without secret injection
	destAddr := req.Host
	if _, _, err := net.SplitHostPort(destAddr); err != nil {
		destAddr = net.JoinHostPort(strings.Trim(destAddr, "[]"), "443")
	}
	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer destConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	closeBoth := func() {
		_ = clientConn.Close()
		_ = destConn.Close()
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer closeBoth()
		_, _ = io.Copy(destConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		defer closeBoth()
		_, _ = io.Copy(clientConn, destConn)
	}()

	wg.Wait()
}

func (fp *ForwardProxy) handleHTTP(w http.ResponseWriter, req *http.Request) {
	host := extractHost(req)

	// Check DNS rebinding in HTTP mode as well (BUG-032)
	if fp.checkDNSRebinding(host) {
		http.Error(w, "SecretHarbor: DNS rebinding to loopback/private IP prohibited", http.StatusForbidden)
		return
	}

	fp.mu.RLock()
	b := fp.broker
	fp.mu.RUnlock()

	if b != nil {
		b.InterceptAndInject(req)
	}

	req.RequestURI = ""
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func extractHost(req *http.Request) string {
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	// Strip port
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Strip IPv6 square brackets if present (e.g. [::1] -> ::1)
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return host
}
