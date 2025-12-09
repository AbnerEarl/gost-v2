package http

import "net/http"

// /Users/frank/go/pkg/mod/github.com/go-gost/x@v0.8.1/connector/http/connector.go
import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/util/socks"
	"github.com/go-gost/x/registry"
)

type contextKey string

const (
	contextKeyRequest contextKey = "gost:original-request"
)

// SaveRequestToContext 保存原始请求到context
func SaveRequestToContext(ctx context.Context, req *http.Request) context.Context {
	return context.WithValue(ctx, contextKeyRequest, req)
}

// RequestFromContext 从context获取原始请求
func RequestFromContext(ctx context.Context) *http.Request {
	if req, ok := ctx.Value(contextKeyRequest).(*http.Request); ok {
		return req
	}
	return nil
}

func init() {
	registry.ConnectorRegistry().Register("http", NewConnector)
}

type httpConnector struct {
	md      metadata
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &httpConnector{
		options: options,
	}
}

func (c *httpConnector) Init(md md.Metadata) (err error) {
	return c.parseMetadata(md)
}

func (c *httpConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	log := c.options.Logger.WithFields(map[string]any{
		"local":   conn.LocalAddr().String(),
		"remote":  conn.RemoteAddr().String(),
		"network": network,
		"address": address,
		"sid":     string(ctxvalue.SidFromContext(ctx)),
	})
	log.Debugf("connect %s/%s", address, network)

	// header:=c.md.header.Clone()
	// header.Set("test-conn",c.)

	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: address},
		Host:       address,
		ProtoMajor: 1,
		ProtoMinor: 1,
		// Header:     c.md.header,
	}

	if req.Header == nil {
		req.Header = http.Header{}
	}

	// =============== 新增：透传原始请求头 ===============
	// 1. 优先从 ctx 中读取 handler 存入的 header 克隆（key: "gost:original-request-headers"）
	if v := ctx.Value("gost:original-request-headers"); v != nil {
		if origHeaders, ok := v.(http.Header); ok && origHeaders != nil {
			log.Debugf("forwarding %d headers from original request", len(origHeaders))
			for key, values := range origHeaders {
				// 跳过 GOST 自身管理或敏感的头
				if key == "Proxy-Authorization" || key == "Proxy-Connection" {
					continue
				}
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
			if log.IsLevelEnabled(logger.TraceLevel) {
				for k, v := range origHeaders {
					log.Tracef("forward header: %s: %v", k, v)
				}
			}
		}
	}

	// =====================================================

	// 3. 复制配置文件中定义的静态头（如果与原始头同名，会被后面的Set覆盖）
	if c.md.header != nil {
		for k, v := range c.md.header {
			req.Header[k] = v
		}
	}

	req.Header.Set("Proxy-Connection", "keep-alive")

	if user := c.options.Auth; user != nil {
		u := user.Username()
		p, _ := user.Password()
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+p)))
		// req.Header.Set("test-pass",p)
		// req.Header.Set("test-user",u)
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		if _, ok := conn.(net.PacketConn); ok {
			err := fmt.Errorf("tcp over udp is unsupported")
			log.Error(err)
			return nil, err
		}
	case "udp", "udp4", "udp6":
		req.Header.Set("X-Gost-Protocol", "udp")
	default:
		err := fmt.Errorf("network %s is unsupported", network)
		log.Error(err)
		return nil, err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	if c.md.connectTimeout > 0 {
		conn.SetDeadline(time.Now().Add(c.md.connectTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	req = req.WithContext(ctx)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	// NOTE: the server may return `Transfer-Encoding: chunked` header,
	// then the Content-Length of response will be unknown (-1),
	// in this case, close body will be blocked, so we leave it untouched.
	// defer resp.Body.Close()

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	if network == "udp" {
		addr, _ := net.ResolveUDPAddr(network, address)
		return socks.UDPTunClientConn(conn, addr), nil
	}

	return conn, nil
}
