package docker_test

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/secretharbor/secretharbor/internal/approval"
	"github.com/secretharbor/secretharbor/internal/docker"
)

func init() {
	os.Setenv("SECRETHARBOR_DISABLE_OS_DIALOG", "1")
}

func TestFindHostDockerSocket(t *testing.T) {
	sock, err := docker.FindHostDockerSocket()
	if err != nil {
		if sock != "" {
			t.Errorf("expected empty string on error")
		}
		return
	}
	if sock == "" {
		t.Errorf("expected non-empty Docker socket path")
	}
}

func TestDockerInterceptorApprovalFlow(t *testing.T) {
	interceptor := docker.NewInterceptor("test-agent")
	defer interceptor.Close()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	upstreamClient, upstreamServer := net.Pipe()
	defer upstreamClient.Close()
	defer upstreamServer.Close()

	interceptor.SetUpstreamDialer(func() (net.Conn, error) {
		return upstreamClient, nil
	})

	// 1. Mock upstream Docker daemon response
	go func() {
		buf := make([]byte, 1024)
		n, _ := upstreamServer.Read(buf)
		if bytes.Contains(buf[:n], []byte("GET /_ping")) {
			_, _ = upstreamServer.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}
	}()

	// 2. Auto-approver goroutine
	go func() {
		for i := 0; i < 50; i++ {
			time.Sleep(10 * time.Millisecond)
			pending := approval.GlobalManager.ListPending()
			for _, req := range pending {
				if req.Capability == "ipc:docker" {
					_ = approval.GlobalManager.Resolve(req.ID, true)
					return
				}
			}
		}
	}()

	// 3. Serve connection
	go interceptor.HandleConnection(serverSide)

	// 4. Send Docker ping from client
	_, err := clientSide.Write([]byte("GET /_ping HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if err != nil {
		t.Fatalf("failed to write to client side: %v", err)
	}

	respBuf := make([]byte, 512)
	n, err := clientSide.Read(respBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("failed to read from client side: %v", err)
	}

	if !bytes.Contains(respBuf[:n], []byte("200 OK")) {
		t.Errorf("expected 200 OK from mock daemon, got:\n%s", string(respBuf[:n]))
	}

	if !interceptor.IsApproved() {
		t.Errorf("expected interceptor to be marked approved")
	}
}

func TestDockerInterceptorDenialFlow(t *testing.T) {
	interceptor := docker.NewInterceptor("test-agent-deny")
	defer interceptor.Close()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	// Auto-denier goroutine
	go func() {
		for i := 0; i < 50; i++ {
			time.Sleep(10 * time.Millisecond)
			pending := approval.GlobalManager.ListPending()
			for _, req := range pending {
				if req.Capability == "ipc:docker" {
					_ = approval.GlobalManager.Resolve(req.ID, false)
					return
				}
			}
		}
	}()

	go interceptor.HandleConnection(serverSide)

	_, _ = clientSide.Write([]byte("GET /_ping HTTP/1.1\r\n\r\n"))

	respBuf := make([]byte, 256)
	n, _ := clientSide.Read(respBuf)

	// Since denied, server closes connection and sends 0 bytes
	if n > 0 {
		t.Errorf("expected 0 bytes returned on denial, got %d", n)
	}
	if interceptor.IsApproved() {
		t.Errorf("interceptor should not be approved after denial")
	}
}

func TestDockerInterceptorLeaseExpiration(t *testing.T) {
	interceptor := docker.NewInterceptor("test-agent-lease")
	defer interceptor.Close()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	upstreamClient, upstreamServer := net.Pipe()
	defer upstreamClient.Close()
	defer upstreamServer.Close()

	interceptor.SetUpstreamDialer(func() (net.Conn, error) {
		return upstreamClient, nil
	})

	go func() {
		buf := make([]byte, 1024)
		_, _ = upstreamServer.Read(buf)
		_, _ = upstreamServer.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	}()

	// Set lease duration: 200ms
	interceptor.SetLeaseDuration(200 * time.Millisecond)

	// Auto-approver
	go func() {
		for i := 0; i < 50; i++ {
			time.Sleep(10 * time.Millisecond)
			pending := approval.GlobalManager.ListPending()
			for _, req := range pending {
				if req.Capability == "ipc:docker" {
					_ = approval.GlobalManager.Resolve(req.ID, true)
					return
				}
			}
		}
	}()

	go interceptor.HandleConnection(serverSide)

	_, _ = clientSide.Write([]byte("GET /_ping HTTP/1.1\r\n\r\n"))
	time.Sleep(50 * time.Millisecond)

	if !interceptor.IsApproved() {
		t.Errorf("expected interceptor to be approved initially")
	}

	// Wait for 200ms lease to expire
	time.Sleep(250 * time.Millisecond)

	if interceptor.IsApproved() {
		t.Errorf("interceptor approval should have expired after lease duration")
	}
}

func TestDockerInterceptorDangerousEndpointFiltering(t *testing.T) {
	interceptor := docker.NewInterceptor("test-agent-filter")
	defer interceptor.Close()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	go interceptor.HandleConnection(serverSide)

	// Send dangerous prune request
	_, _ = clientSide.Write([]byte("POST /system/prune HTTP/1.1\r\nHost: localhost\r\n\r\n"))

	respBuf := make([]byte, 512)
	n, _ := clientSide.Read(respBuf)
	resp := string(respBuf[:n])

	if !strings.Contains(resp, "403 Forbidden") {
		t.Errorf("expected 403 Forbidden for filtered dangerous endpoint, got: %s", resp)
	}
}
