package gost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
)

type httpConnector struct {
	User *url.Userinfo
}

// HTTPConnector creates a Connector for HTTP proxy client.
// It accepts an optional auth info for HTTP Basic Authentication.
func HTTPConnector(user *url.Userinfo) Connector {
	return &httpConnector{User: user}
}

func (c *httpConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *httpConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// === Traffic Logging Inject: Capture Request Body ===
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())

	// CONNECT 无法读取真实 HTTP 请求体，只记录元信息
	if EnableTrafficLog {
		go func() {
			t := &TrafficLog{
				ID:       requestID,
				Proto:    "http-connect",
				ClientIP: clientIP,
				TargetIP: address,
				URL:      conn.RemoteAddr().String(),
				Method:   "CONNECT",
				Time:     time.Now(),
			}
			Write(t)
		}()
	}

	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: address},
		Host:       address,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Proxy-Connection", "keep-alive")

	user := opts.User
	if user == nil {
		user = c.User
	}

	if user != nil {
		u := user.Username()
		p, _ := user.Password()
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+p)))
	}

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		dump, _ := httputil.DumpRequest(req, true)
		log.Log("[http ConnectContext]", req.URL.String(), req.URL.Path, req.URL.RequestURI(), string(dump))
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}

	if Debug {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Log(req.URL.String(), req.URL.Path, req.URL.RequestURI(), string(dump))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	return conn, nil
}

type httpHandler struct {
	options *HandlerOptions
}

// HTTPHandler creates a server Handler for HTTP proxy server.
func HTTPHandler(opts ...HandlerOption) Handler {
	h := &httpHandler{}
	h.Init(opts...)
	return h
}

func (h *httpHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *httpHandler) Handle(conn net.Conn) {
	defer conn.Close()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Logf("[http] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	defer req.Body.Close()

	h.handleRequest(conn, req)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (h *httpHandler) handleRequest(conn net.Conn, req *http.Request) {
	if req == nil {
		return
	}

	// === Traffic Logging Inject: Capture Request Body ===
	var reqBuf = &limitedBuffer{limit: MaxBodyLogBytes}
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())

	if EnableTrafficLog && req.Body != nil {
		req.Body = io.NopCloser(io.TeeReader(req.Body, reqBuf))
	}

	// try to get the actual host.
	if v := req.Header.Get("Gost-Target"); v != "" {
		if h, err := decodeServerName(v); err == nil {
			req.Host = h
		}
	}

	host := req.Host
	if _, port, _ := net.SplitHostPort(host); port == "" {
		host = net.JoinHostPort(host, "80")
	}

	u, _, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	if u != "" {
		u += "@"
	}
	log.Logf("[http handleRequest] %s%s -> %s -> %s",
		u, conn.RemoteAddr(), h.options.Node.String(), host)

	if Debug {
		dump, _ := httputil.DumpRequest(req, true)
		log.Logf("[http handleRequest] %s -> %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), req.URL.String(), req.URL.Path, req.URL.RequestURI(), string(dump))
	}

	req.Header.Del("Gost-Target")

	resp := &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}

	proxyAgent := DefaultProxyAgent
	if h.options.ProxyAgent != "" {
		proxyAgent = h.options.ProxyAgent
	}
	resp.Header.Add("Proxy-Agent", proxyAgent)

	if !Can("tcp", host, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[http] %s - %s : Unauthorized to tcp connect to %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		resp.StatusCode = http.StatusForbidden

		if Debug {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), string(dump))
		}

		resp.Write(conn)
		return
	}

	if h.options.Bypass.Contains(host) {
		resp.StatusCode = http.StatusForbidden

		log.Logf("[http] %s - %s bypass %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		if Debug {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), string(dump))
		}

		resp.Write(conn)
		return
	}

	if !h.authenticate(conn, req, resp) {
		return
	}

	if req.Method == "PRI" || (req.Method != http.MethodConnect && req.URL.Scheme != "http") {
		resp.StatusCode = http.StatusBadRequest

		if Debug {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Logf("[http] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), string(dump))
		}

		resp.Write(conn)
		return
	}

	req.Header.Del("Proxy-Authorization")

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var err error
	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(host)
		if err != nil {
			log.Logf("[http] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", host)
		log.Log("[route]", buf.String())

		// forward http request
		lastNode := route.LastNode()
		if req.Method != http.MethodConnect &&
			lastNode.Protocol == "http" &&
			!h.options.HTTPTunnel {
			err = h.forwardRequest(conn, req, route)
			if err == nil {
				return
			}
			log.Logf("[http] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		cc, err = route.Dial(host,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}
		log.Logf("[http] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	if err != nil {
		resp.StatusCode = http.StatusServiceUnavailable

		if Debug {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), string(dump))
		}

		resp.Write(conn)
		return
	}
	defer cc.Close()

	if req.Method != http.MethodConnect {
		h.handleProxy(conn, cc, req)
		return
	} else {
		h.handleMITMConnect(conn, req, clientIP, requestID)
		return
	}

}

func interceptHTTP(client net.Conn, server net.Conn, clientIP, requestID string) {
	clientReader := bufio.NewReader(client)
	serverReader := bufio.NewReader(server)

	var reqBuf, respBuf limitedBuffer
	reqBuf.limit = 65535 * 2
	respBuf.limit = 65535 * 2

	for {
		// ---- 读取客户端 HTTP 请求 ----
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			// 读取客户端请求失败（包括 EOF），结束拦截
			return
		}
		// 代理到 origin server 时必须清空 RequestURI
		req.RequestURI = ""

		// 捕获并缓存请求体（如果有）
		if req.Body != nil {
			// 将请求体读到 reqBuf，并把 Body 替换为新的 reader 以便后续写给 server
			io.Copy(&reqBuf, req.Body)
			req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(reqBuf.Bytes()))

		}

		// ---- 发送请求到目标服务器 ----
		// 删除代理相关头，确保写给 server 的头合规（可根据需要保留 Host）
		req.Header.Del("Proxy-Connection")
		if err = req.Write(server); err != nil {
			return
		}

		// ---- 读取目标服务器返回 ----
		resp, err := http.ReadResponse(serverReader, req)
		if err != nil {
			return
		}

		// ---- 关键：不要预先把 body 全部读取到内存然后再消费 ----
		// 使用 TeeReader：当我们把响应写回客户端时，读取 resp.Body 会同时把数据写到 respBuf
		if resp.Body != nil {
			resp.Body = io.NopCloser(io.TeeReader(resp.Body, &respBuf))
		}

		// ---- 把响应转发回客户端（resp.Write 会读取 resp.Body 并触发 TeeReader） ----
		if err = resp.Write(client); err != nil {
			// 确保关闭响应体
			if resp.Body != nil {
				io.Copy(io.Discard, resp.Body) // drain if needed
				resp.Body.Close()
			}
			return
		}

		// resp.Write 已读取并发送了 body（TeeReader 已把数据写入 respBuf）
		// 现在我们可以异步记录日志（respBuf 包含已读响应体）
		if EnableTrafficLog {
			// 如果 resp.Body 尚未关闭，关闭它
			if resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			// 复制一份 req 和 resp 头/内容去记录（避免竞争）
			go func(r *http.Request, rp *http.Response, reqB, respB []byte) {
				// 注意：logMITMTraffic 的入参需要 req 和 resp 原对象；我们在这里复用已有的 req/rp
				// 如果 logMITMTraffic 需要完整的 body bytes，它会从 reqB/respB 中获取
				// 为最少改动，调用原函数但手动填充缓冲区变量
				// Reconstruct bodies for logging:
				// req.Body is already consumed; use reqB; resp.Body consumed, respB has content.
				// So we create new Request/Response copies or modify fields appropriately.
				// For simplicity, call a thin wrapper to avoid changing logMITMTraffic signature:
				reqCopy := r.Clone(context.Background())
				if len(reqB) > 0 {
					reqCopy.Body = io.NopCloser(bytes.NewReader(reqB))
				} else {
					reqCopy.Body = nil
				}

				respCopy := &http.Response{
					StatusCode: rp.StatusCode,
					ProtoMajor: rp.ProtoMajor,
					ProtoMinor: rp.ProtoMinor,
					Header:     rp.Header.Clone(),
					Body:       io.NopCloser(bytes.NewReader(respB)),
				}

				// Note: originReq header proxy_extra_info may be empty here; you can pass "" or adapt as needed.
				logMITMTraffic(requestID, clientIP, req.Header.Get("proxy_extra_info"), "http", reqCopy, respCopy, &limitedBuffer{buf: *bytes.NewBuffer(reqB), limit: len(reqB)}, &limitedBuffer{buf: *bytes.NewBuffer(respB), limit: len(respB)})
			}(req, resp, reqBuf.Bytes(), respBuf.Bytes())
		} else {
			// 如果没有启用日志，确保关闭 body
			if resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}
}

func (h *httpHandler) handleProxy(rw, cc io.ReadWriter, req *http.Request) (err error) {
	req.Header.Del("Proxy-Connection")

	if err = req.Write(cc); err != nil {
		return err
	}

	ch := make(chan error, 1)

	go func() {
		ch <- copyBuffer(rw, cc)
	}()

	for {
		err := func() error {
			req, err := http.ReadRequest(bufio.NewReader(rw))
			if err != nil {
				return err
			}

			if Debug {
				dump, _ := httputil.DumpRequest(req, false)
				log.Log(string(dump))
			}

			req.Header.Del("Proxy-Connection")

			if err = req.Write(cc); err != nil {
				return err
			}
			return nil
		}()
		ch <- err

		if err != nil {
			break
		}
	}

	return <-ch
}

// handleMITMConnect 处理MITM模式下的CONNECT请求
// bufferedConn 与之前一致，用于把 peek 的 bytes 放回到读取流中
type bufferedConn struct {
	net.Conn
	buf *bytes.Reader
}

func newBufferedConn(c net.Conn, pre []byte) net.Conn {
	var r *bytes.Reader
	if len(pre) > 0 {
		r = bytes.NewReader(pre)
	} else {
		r = bytes.NewReader(nil)
	}
	return &bufferedConn{Conn: c, buf: r}
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if b.buf != nil && b.buf.Len() > 0 {
		return b.buf.Read(p)
	}
	return b.Conn.Read(p)
}

// closeWriteIfPossible 尝试对 TCP 连接做半关闭（CloseWrite），若不可用则关闭整个连接
func closeWriteIfPossible(c net.Conn) {
	// net.Conn may implement interface with CloseWrite (e.g. *net.TCPConn)
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	// For other types (e.g. tls.Conn) fallback to Close()
	_ = c.Close()
}

// tunnel 阻塞直到双向复制完成，再返回。
// 使用 CloseWrite 半关闭来通知另一端 EOF，从而优雅结束。
func tunnel(client net.Conn, targetAddr string) error {
	server, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// 从 client -> server
	go func() {
		defer wg.Done()
		_, _ = io.Copy(server, client)
		// 关写端通知 server 已无更多数据
		closeWriteIfPossible(server)
	}()

	// 从 server -> client
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, server)
		// 关写端通知 client 已无更多数据
		closeWriteIfPossible(client)
	}()

	// 等待两个方向都结束
	wg.Wait()

	// 关闭 server socket（client 在外层会被 defer 关闭）
	_ = server.Close()
	return nil
}

// 检测首包是否为 TLS ClientHello（简单但实用）
func isTLSClientHello(b []byte) bool {
	// TLS record header: type(1)=0x16, version(2)=0x03,0x01/02/03...
	// also accept SSLv2 ClientHello legacy (starts with 0x80 ..) - optional
	if len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 {
		return true
	}
	// some SSLv2 style ClientHello begin with 0x80 or 0x00 with len; not needed in most cases
	return false
}

// ---- 替换 handleMITMConnect ----
func (h *httpHandler) handleMITMConnect(conn net.Conn, req *http.Request, clientIP, requestID string) error {
	host := req.Host
	// 如果没有端口，保守地假定 443（但我们会动态检测客户端是否为 TLS）
	if _, port, _ := net.SplitHostPort(host); port == "" {
		host = net.JoinHostPort(host, "443")
	}

	log.Logf("[http] [MITM] %s -> %s : received CONNECT, will probe client to decide MITM or tunnel", clientIP, host)

	// 1. 返回 200 Connection established（客户端预期）
	proxyAgent := h.getProxyAgent()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 Connection established",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Proxy-Agent": []string{proxyAgent},
		},
	}
	if err := resp.Write(conn); err != nil {
		log.Logf("[http] [MITM] %s -> %s : failed to write CONNECT response: %v", clientIP, host, err)
		return err
	}

	// 2. 从客户端连接上 peek 一些字节，检测是 TLS 还是明文 HTTP
	peekBuf := make([]byte, 5)
	// 设置短超时防止 hang（几秒）
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(peekBuf)
	// 清除 deadline
	conn.SetReadDeadline(time.Time{})
	if err != nil && err != io.EOF {
		// 若客户端很快关闭连接或读出错，直接返回
		if Debug {
			log.Logf("[http] [MITM] %s -> %s : peek read err: %v", clientIP, host, err)
		}
		return err
	}
	peek := peekBuf[:n]

	// 如果 peek 出现的是明文 HTTP 请求（例如 'G' 'E' 'T' 等 ASCII）或其它非 TLS 数据，
	// 则我们应当建立原始隧道（不要做 MITM）。
	if n > 0 && !isTLSClientHello(peek) {
		log.Logf("[http] [MITM] %s -> %s : detected non-TLS (likely plaintext HTTP) after CONNECT, perform raw tunnel or intercepted-http", clientIP, host)

		// 包装后端连接
		bc := newBufferedConn(conn, peek)

		// 如果开启流量日志 -> 使用 HTTP 层解析并记录（使用你已有的 interceptHTTP）
		if EnableTrafficLog {
			server, err := net.DialTimeout("tcp", host, 10*time.Second)
			if err != nil {
				log.Logf("[http] [MITM] %s -> %s : dial target failed: %v", clientIP, host, err)
				return err
			}
			// 不要在这里并发 goroutine，直接调用 interceptHTTP，会阻塞直到完成（与 tunnel 行为一致）
			interceptHTTP(bc, server, clientIP, requestID)
			// interceptHTTP 函数会在合适时关闭连接或返回（当前实现为直接 return，当读写结束会退出）
			return nil
		}

		// 否则不开启日志 -> 快速高效的二进制隧道（阻塞直到完成）
		return tunnel(bc, host)
	}

	// 否则看起来像 TLS ClientHello，则我们继续进行 MITM（生成证书然后 tls.Server）
	log.Logf("[http] [MITM] %s -> %s : detected TLS ClientHello, proceed with MITM", clientIP, host)

	// 为了不丢掉已 peek 的 ClientHello，使用 bufferedConn
	clientConn := newBufferedConn(conn, peek)

	// 生成 MITM cert 等（你原来的逻辑）
	tlsConfig, err := h.getMITMTLSConfig(host)
	if err != nil {
		log.Logf("[http] [MITM getMITMTLSConfig] %s -> %s : TLS getMITMTLSConfig failed: %v", clientIP, host, err)
		return err
	}

	tlsServer := tls.Server(clientConn, tlsConfig)
	if err := tlsServer.Handshake(); err != nil {
		log.Logf("[http] [MITM] %s -> %s : TLS handshake failed: %v", clientIP, host, err)
		return err
	}

	// 读取解密后的 HTTP 请求（支持 keep-alive 循环）
	decryptedReader := bufio.NewReader(tlsServer)
	for {
		decryptedReq, err := http.ReadRequest(decryptedReader)
		if err != nil {
			if Debug {
				log.Logf("[http] [MITM] %s -> %s : read decrypted request error: %v", clientIP, host, err)
			}
			return err
		}

		// 保证 Host 字段正确（使用原始 CONNECT 的 host）
		decryptedReq.Host = req.Host
		decryptedReq.RequestURI = ""

		// 交由 MITM 的 proxy 处理（你的 handleProxyMITM）
		if err := h.handleProxyMITM(tlsServer, decryptedReq, req, host, requestID, clientIP); err != nil {
			return err
		}

		// 若客户端不想 keep-alive，则结束
		if connHdr := decryptedReq.Header.Get("Connection"); strings.EqualFold(connHdr, "close") {
			return nil
		}
	}
}

func (h *httpHandler) getProxyAgent() string {
	if h.options.ProxyAgent != "" {
		return h.options.ProxyAgent
	}
	return DefaultProxyAgent
}

func (h *httpHandler) getMITMTLSConfig(host string) (*tls.Config, error) {
	// 获取CA证书路径
	caCertPath := "/home/mygost/ca/ca.crt"
	caKeyPath := "/home/mygost/ca/ca.key"

	if caCertPath == "" || caKeyPath == "" {
		return nil, fmt.Errorf("CA certificate path not configured")
	}

	// 读取CA证书和私钥
	caCert, caKey, err := h.loadCACertificate(caCertPath, caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}

	// 为 host 动态生成叶子证书（关键！）
	cert, err := h.generateLeafCertificate(host, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf cert for %s: %w", host, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}, nil
}

// 加载CA证书和私钥
func (h *httpHandler) loadCACertificate(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// 读取CA证书
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// 读取CA私钥
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// 尝试PKCS8格式
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, nil, err
		}
		caKey = pkcs8Key.(*rsa.PrivateKey)
	}

	return caCert, caKey, nil
}

// 动态生成叶子证书（由CA签名）
func (h *httpHandler) generateLeafCertificate(host string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, error) {
	// 生成新的RSA私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 解析host和端口
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		// 没有端口
		hostname = host
	}

	// 构建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"GOST-MITM"},
			Country:      []string{"CN"},
			Province:     []string{"Beijing"},
			Locality:     []string{"Beijing"},
			CommonName:   hostname, // 关键：设置为域名
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour), // 1天有效期
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// 添加SAN扩展（关键！必须包含域名）
	template.DNSNames = []string{hostname}
	if strings.HasPrefix(hostname, "www.") {
		// 同时添加不带www的域名
		template.DNSNames = append(template.DNSNames, hostname[4:])
	}

	// 使用CA签名生成证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 编码为PEM格式
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// 加载为tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

// handleProxyMITM - 修复：清理代理头、确保写给 origin server 时使用相对请求行（非 absolute-form），设置 Host，
// 并根据 scheme 决定是否对目标建立 TLS 客户端连接。
// 注意：这里 req 是从 TLS 解密后得到的请求（来自客户端）， originReq 是最初的 CONNECT 请求（保留一些元信息）。
func (h *httpHandler) handleProxyMITM(rw io.ReadWriter, req, originReq *http.Request, host, requestID, clientIP string) error {
	var reqBuf, respBuf limitedBuffer
	reqBuf.limit = MaxBodyLogBytes
	respBuf.limit = MaxBodyLogBytes

	// 解析目标主机名和端口（host 可能包含端口）
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
		// CONNECT 一般对应 https
		port = "443"
		host = net.JoinHostPort(hostname, port)
	}

	targetAddr := host

	// ---- 清理并准备请求，将其转换为发给 origin server 的形式 ----
	// 删除代理特有头
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")
	// 如果客户端带有 Connection: keep-alive/close，保留其语义，但不应带 Proxy-Connection
	// 设置请求 Host 字段（重要）
	req.Host = originReq.Host // 保留原始 CONNECT 的 host (带端口)
	// Ensure RequestURI empty so http.Request.Write will write path-form (not absolute-form)
	req.RequestURI = ""

	// 如果 req.URL 是绝对 URL，则把 Scheme/Host 清掉，避免写成 absolute-form。
	if req.URL != nil && req.URL.IsAbs() {
		// 备份绝对URL部分（可用于日志），然后清理
		req.URL.Scheme = ""
		req.URL.Host = ""
	}

	// 捕获请求体用于流量日志
	if req.Body != nil {
		req.Body = io.NopCloser(io.TeeReader(req.Body, &reqBuf))
	}

	// ---- 与目标服务器建立连接（如果是 HTTPS，则使用 tls.Dial） ----
	var cc net.Conn
	if true { // CONNECT -> HTTPS, 但是我们仍按端口判断是否启用 TLS
		if port == "443" {
			log.Logf("[MITM] %s -> %s : establishing TLS connection to target", clientIP, targetAddr)
			tlsConfig := &tls.Config{
				ServerName: hostname,
				MinVersion: tls.VersionTLS12,
			}
			cc, err = tls.Dial("tcp", targetAddr, tlsConfig)
			if err != nil {
				log.Logf("[MITM] Failed to establish TLS connection to %s: %v", targetAddr, err)
				return fmt.Errorf("tls dial failed: %w", err)
			}
		} else {
			// 非 443 端口，按需使用明文（适配一些站点）
			log.Logf("[MITM] %s -> %s : establishing plaintext connection", clientIP, targetAddr)
			cc, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
			if err != nil {
				log.Logf("[MITM] Failed to connect to %s: %v", targetAddr, err)
				return err
			}
		}
	} else {
		// （保留结构）如果以后需要按 req.URL.Scheme 决定则可修改这里
	}

	defer cc.Close()

	// ---- 把请求写给目标服务器（注意：不要写成 proxy absolute-form） ----
	if err := req.Write(cc); err != nil {
		log.Logf("[MITM] Failed to write request to target %s: %v", targetAddr, err)
		return err
	}

	// ---- 读取响应 ----
	// 用 TeeReader 捕获响应体
	respReader := bufio.NewReader(cc)
	resp, err := http.ReadResponse(respReader, req)
	if err != nil {
		log.Logf("[MITM] Failed to read response from target %s: %v", targetAddr, err)
		return err
	}
	// 将响应体也 Tee 以便日志
	if resp.Body != nil {
		resp.Body = io.NopCloser(io.TeeReader(resp.Body, &respBuf))
	}

	// ---- 写回给客户端（TLS层的 rw） ----
	if err := resp.Write(rw); err != nil {
		log.Logf("[MITM] Failed to write response back to client: %v", err)
		_ = resp.Body.Close()
		return err
	}

	// 触发读取剩余 body（用于记录流量），并异步写日志
	if EnableTrafficLog {
		if resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
		}
		go logMITMTraffic(requestID, clientIP, originReq.Header.Get("proxy_extra_info"), "https", req, resp, &reqBuf, &respBuf)
	}

	// 关闭响应 body
	if resp.Body != nil {
		resp.Body.Close()
	}

	return nil
}

func (h *httpHandler) handleProxy2(rw, cc io.ReadWriter, req *http.Request) error {
	clientIP, _, _ := net.SplitHostPort(req.RemoteAddr)
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())

	var reqBuf = &limitedBuffer{limit: MaxBodyLogBytes}
	var respBuf = &limitedBuffer{limit: MaxBodyLogBytes}

	// 1. 删除代理相关头
	req.Header.Del("Proxy-Connection")
	extraInfo := req.Header.Get("proxy_extra_info")
	req.Header.Del("proxy_extra_info")

	req.Body = io.NopCloser(io.TeeReader(req.Body, reqBuf))

	// 2. 只发送一次请求
	if err := req.Write(cc); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	// 3. 同步读取响应（无需并发）
	resp, err := http.ReadResponse(bufio.NewReader(cc), req)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	// 4. 记录响应体（如需）
	resp.Body = io.NopCloser(io.TeeReader(resp.Body, respBuf))

	// 5. 将响应写回客户端
	if err = resp.Write(rw); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	// 6. 记录流量日志（异步）
	if EnableTrafficLog {
		if resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
		}
		go logMITMTraffic(requestID, clientIP, extraInfo, "http", req, resp, reqBuf, respBuf)
	}

	return nil
}

// 异步记录MITM流量日志
func logMITMTraffic(requestID, clientIP, extraInfo, proto string, req *http.Request, resp *http.Response, reqBuf, respBuf *limitedBuffer) {
	// 读取Body内容
	reqBody := reqBuf.Bytes()
	respBody := respBuf.Bytes()

	// 请求头
	reqHeaders := make(map[string][]string)
	for k, v := range req.Header {
		reqHeaders[k] = v
	}

	// 响应头
	respHeaders := make(map[string][]string)
	for k, v := range resp.Header {
		respHeaders[k] = v
	}

	t := &TrafficLog{
		ID:             requestID,
		Proto:          proto,
		ClientIP:       clientIP,
		TargetIP:       req.Host,
		URL:            fmt.Sprintf("%s://%s%s", proto, req.Host, req.URL.Path),
		Method:         req.Method,
		Query:          req.URL.RawQuery,
		ReqHeaders:     reqHeaders,
		ReqBodyBase64:  base64.StdEncoding.EncodeToString(reqBody),
		RespHeaders:    respHeaders,
		RespBodyBase64: base64.StdEncoding.EncodeToString(respBody),
		Status:         resp.StatusCode,
		Time:           time.Now(),
	}
	Write(t)

	// 实时打印摘要
	log.Logf("[TRAFFIC] ID=%s,%s | %s %s | Status=%d | Req=%db Resp=%db",
		requestID, extraInfo, req.Method, req.URL.String(), resp.StatusCode,
		len(reqBody), len(respBody))
}

func (h *httpHandler) authenticate(conn net.Conn, req *http.Request, resp *http.Response) (ok bool) {
	if Debug {
		dump, _ := httputil.DumpRequest(req, true)
		log.Logf("[http authenticate] %s -> %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), req.URL.String(), req.URL.Path, req.URL.RequestURI(), string(dump))
	}
	u, p, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	if Debug && (u != "" || p != "") {
		log.Logf("[http] %s -> %s : Authorization '%s' '%s'",
			conn.RemoteAddr(), conn.LocalAddr(), u, p)
	}
	if h.options.Authenticator == nil || h.options.Authenticator.Authenticate(u, p) {
		return true
	}

	// probing resistance is enabled, and knocking host is mismatch.
	if ss := strings.SplitN(h.options.ProbeResist, ":", 2); len(ss) == 2 &&
		(h.options.KnockingHost == "" || !strings.EqualFold(req.URL.Hostname(), h.options.KnockingHost)) {
		resp.StatusCode = http.StatusServiceUnavailable // default status code

		switch ss[0] {
		case "code":
			resp.StatusCode, _ = strconv.Atoi(ss[1])
		case "web":
			url := ss[1]
			if !strings.HasPrefix(url, "http") {
				url = "http://" + url
			}
			if r, err := http.Get(url); err == nil {
				resp = r
			}
		case "host":
			cc, err := net.Dial("tcp", ss[1])
			if err == nil {
				defer cc.Close()

				req.Write(cc)
				log.Logf("[http] %s <-> %s : forward to %s",
					conn.RemoteAddr(), conn.LocalAddr(), ss[1])
				transport(conn, cc)
				log.Logf("[http] %s >-< %s : forward to %s",
					conn.RemoteAddr(), conn.LocalAddr(), ss[1])
				return
			}
		case "file":
			f, _ := os.Open(ss[1])
			if f != nil {
				resp.StatusCode = http.StatusOK
				if finfo, _ := f.Stat(); finfo != nil {
					resp.ContentLength = finfo.Size()
				}
				resp.Header.Set("Content-Type", "text/html")
				resp.Body = f
			}
		}
	}

	if resp.StatusCode == 0 {
		log.Logf("[http] %s <- %s : proxy authentication required",
			conn.RemoteAddr(), conn.LocalAddr())
		resp.StatusCode = http.StatusProxyAuthRequired
		resp.Header.Add("Proxy-Authenticate", "Basic realm=\"gost\"")
		if strings.ToLower(req.Header.Get("Proxy-Connection")) == "keep-alive" {
			// XXX libcurl will keep sending auth request in same conn
			// which we don't supported yet.
			resp.Header.Add("Connection", "close")
			resp.Header.Add("Proxy-Connection", "close")
		}
	} else {
		resp.Header = http.Header{}
		resp.Header.Set("Server", "nginx/1.14.1")
		resp.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		if resp.StatusCode == http.StatusOK {
			resp.Header.Set("Connection", "keep-alive")
		}
	}

	if Debug {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Logf("[http] %s <- %s\n%s",
			conn.RemoteAddr(), conn.LocalAddr(), string(dump))
	}

	resp.Write(conn)
	return
}

func (h *httpHandler) forwardRequest(conn net.Conn, req *http.Request, route *Chain) error {
	if route.IsEmpty() {
		return nil
	}

	if Debug {
		dump, _ := httputil.DumpRequest(req, true)
		log.Logf("[http forwardRequest] %s -> %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), req.URL.String(), req.URL.Path, req.URL.RequestURI(), string(dump))
	}

	host := req.Host
	var userpass string

	if user := route.LastNode().User; user != nil {
		u := user.Username()
		p, _ := user.Password()
		userpass = base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
	}

	cc, err := route.Conn()
	if err != nil {
		return err
	}
	defer cc.Close()

	errc := make(chan error, 1)
	go func() {
		errc <- copyBuffer(conn, cc)
	}()

	go func() {
		for {
			if userpass != "" {
				req.Header.Set("Proxy-Authorization", "Basic "+userpass)
			}

			cc.SetWriteDeadline(time.Now().Add(WriteTimeout))
			if !req.URL.IsAbs() {
				req.URL.Scheme = "http" // make sure that the URL is absolute
			}
			err := req.WriteProxy(cc)
			if err != nil {
				log.Logf("[http] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
				errc <- err
				return
			}
			cc.SetWriteDeadline(time.Time{})

			req, err = http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				errc <- err
				return
			}

			if Debug {
				dump, _ := httputil.DumpRequest(req, true)
				log.Logf("[http] %s -> %s\n%s",
					conn.RemoteAddr(), conn.LocalAddr(), req.URL.String(), req.URL.Path, req.URL.RequestURI(), string(dump))
			}
		}
	}()

	log.Logf("[http] %s <-> %s", conn.RemoteAddr(), host)
	<-errc
	log.Logf("[http] %s >-< %s", conn.RemoteAddr(), host)

	if EnableTrafficLog {
		t := &TrafficLog{
			ID:       fmt.Sprintf("%d", time.Now().UnixNano()),
			Proto:    "http-forward",
			ClientIP: conn.RemoteAddr().String(),
			TargetIP: host,
			URL:      req.URL.String(),
			Method:   req.Method,
			Time:     time.Now(),
		}
		Write(t)
	}

	return nil
}

func basicProxyAuth(proxyAuth string) (username, password string, ok bool) {
	if proxyAuth == "" {
		return
	}

	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}

	return cs[:s], cs[s+1:], true
}
