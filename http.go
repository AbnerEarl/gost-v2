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
		log.Logf("[handleProxy] %s <- %s,%s,%s\n%s", conn.RemoteAddr(), conn.LocalAddr(), req.URL.Scheme, req.Proto, req.URL)
		err = h.handleProxy(conn, cc, req)
	} else {
		//if req.Method == http.MethodConnect && strings.Contains(req.Proto, "https") || strings.Contains(req.URL.Scheme, "https")
		log.Logf("[handleMITMConnect] %s <- %s,%s,%s\n%s", conn.RemoteAddr(), conn.LocalAddr(), req.URL.Scheme, req.Proto, req.URL)
		err = h.handleMITMConnect(conn, req, clientIP, requestID)
	}

	//if err != nil {
	//	log.Logf("[forwardRequest] %s <- %s,%s,%s\n%s", conn.RemoteAddr(), conn.LocalAddr(), req.URL.Scheme, req.Proto, req.URL)
	//	if err = h.forwardRequest(conn, req, route); err == nil {
	//		return
	//	}
	//}

	if err == nil {
		return
	}

	log.Logf("[other] %s <- %s,%s,%s\n%s", conn.RemoteAddr(), conn.LocalAddr(), req.URL.Scheme, req.Proto, req.URL)

	b := []byte("HTTP/1.1 200 Connection established\r\n" +
		"Proxy-Agent: " + proxyAgent + "\r\n\r\n")
	if Debug {
		log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), string(b))
	}
	conn.Write(b)

	log.Logf("[http] %s <-> %s", conn.RemoteAddr(), host)
	transport(conn, cc)
	//transportWithHTTPLog(conn, cc, clientIP, requestID)
	log.Logf("[http] %s >-< %s", conn.RemoteAddr(), host)
}

func transportWithHTTPLog(client, server net.Conn, clientIP, requestID string) {

	// ========== 方向 1：client -> server（拦截请求）==========
	reqReader := bufio.NewReader(client)
	var reqBuf = &limitedBuffer{limit: MaxBodyLogBytes}
	var respBuf = &limitedBuffer{limit: MaxBodyLogBytes}

	// 尝试读取 HTTP 请求
	req, err := http.ReadRequest(reqReader)
	if err != nil {
		// 不是 HTTP 请求？直接降级透明拷贝
		io.Copy(server, io.MultiReader(bytes.NewReader(reqBuf.Bytes()), reqReader))
		go io.Copy(client, server)
		return
	}

	// 读取完整请求体
	if req.Body != nil {
		body, _ := io.ReadAll(io.TeeReader(req.Body, reqBuf))
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body)) // 恢复 Body 给下游使用
	}

	// 把请求写往 server
	if err := req.Write(server); err != nil {
		return
	}

	// ========== 方向 2：server -> client（拦截响应）==========
	go func() {
		respReader := bufio.NewReader(server)

		for {
			resp := &http.Response{}

			// 读取 HTTP 响应
			r, err := http.ReadResponse(respReader, req)
			if err != nil {
				// 不是合法 HTTP 响应，降级为直接拷贝剩余数据
				//io.Copy(client, io.MultiReader(bytes.NewReader(respReader.), respReader))
				transport(client, server)
				return
			}
			resp = r

			// 读取响应体
			if resp.Body != nil {
				body, _ := io.ReadAll(io.TeeReader(resp.Body, respBuf))
				resp.Body.Close()
				resp.Body = io.NopCloser(bytes.NewReader(body)) // 恢复 Body
			}

			// ====== 调用你的日志记录函数 ======
			logMITMTraffic(
				requestID,
				clientIP,
				"HTTP-PLAIN",
				req,
				resp,
				reqBuf,
				respBuf,
			)

			// 写回客户端
			if err := resp.Write(client); err != nil {
				return
			}

			// 判断是否 keep-alive
			if resp.Close || req.Close {
				return
			}

			// 尝试读取下一次请求（HTTP pipeline 或 keep-alive）
			req, err = http.ReadRequest(reqReader)
			if err != nil {
				return
			}
			// 读取请求体
			if req.Body != nil {
				body, _ := io.ReadAll(io.TeeReader(req.Body, reqBuf))
				req.Body.Close()
				req.Body = io.NopCloser(bytes.NewReader(body))
			}
			req.Write(server)
		}
	}()

	// 主 goroutine 阻塞，与 server->client goroutine 协同退出
	io.Copy(io.Discard, client)
}

// handleMITMConnect 处理MITM模式下的CONNECT请求
func (h *httpHandler) handleMITMConnect(conn net.Conn, req *http.Request, clientIP, requestID string) error {
	host := req.Host
	if _, port, _ := net.SplitHostPort(host); port == "" {
		host = net.JoinHostPort(host, "443")
	}

	log.Logf("[http] [MITM] %s -> %s : upgrading CONNECT to plaintext proxy", clientIP, host)

	// 1. 返回200连接建立（但不进入隧道模式）
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

	// 2. 劫持客户端连接，将其转换为TLS服务器（使用MITM证书）
	tlsConfig, err := h.getMITMTLSConfig(host) // 动态生成目标网站的证书
	if err != nil {
		log.Logf("[http] [MITM getMITMTLSConfig] %s -> %s : TLS getMITMTLSConfig failed: %v", clientIP, host, err)

	}
	tlsConn := tls.Server(conn, tlsConfig)

	// 3. 在TLS层之上进行HTTP明文通信
	if err = tlsConn.Handshake(); err != nil {
		log.Logf("[http] [MITM] %s -> %s : TLS handshake failed: %v", clientIP, host, err)
		return err
	}

	// 4. 读取解密后的HTTP请求
	decryptedReq, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		log.Logf("[http] [MITM] %s -> %s : failed to read decrypted request: %v", clientIP, host, err)
		return err
	}
	defer decryptedReq.Body.Close()

	// 5. 强制设置URL Scheme为https（重要！）
	if !decryptedReq.URL.IsAbs() {
		decryptedReq.URL.Scheme = "https"
		decryptedReq.URL.Host = req.Host // 保留原始Host
	}

	// 6. 进入明文代理处理流程
	return h.handleProxyMITM(tlsConn, decryptedReq, req, host, requestID, clientIP)
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

func (h *httpHandler) handleProxyMITM(rw io.ReadWriter, req, originReq *http.Request, host, requestID, clientIP string) error {
	var reqBuf, respBuf limitedBuffer
	reqBuf.limit = MaxBodyLogBytes
	respBuf.limit = MaxBodyLogBytes

	// 提取域名和端口
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		// 没有端口，根据Scheme判断
		hostname = host
		if req.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
		host = net.JoinHostPort(hostname, port)
	}

	// 构建目标地址
	targetAddr := host

	// === 关键修复：判断是否为HTTPS端口，自动启用TLS ===
	var cc net.Conn
	if req.URL.Scheme == "https" {
		log.Logf("[MITM] %s -> %s : establishing TLS connection to target", clientIP, targetAddr)

		// 创建TLS配置（作为客户端连接目标服务器）
		tlsConfig := &tls.Config{
			ServerName: hostname, // SNI，必须设置
			MinVersion: tls.VersionTLS12,
		}

		// 建立TLS连接
		cc, err = tls.Dial("tcp", targetAddr, tlsConfig)
		if err != nil {
			log.Logf("[MITM] Failed to establish TLS connection to %s: %v", targetAddr, err)
			return fmt.Errorf("tls dial failed: %w", err)
		}
		log.Logf("[MITM] TLS connection established to %s", targetAddr)
	} else {
		// 明文HTTP连接
		log.Logf("[MITM] %s -> %s : establishing plaintext connection", clientIP, targetAddr)
		cc, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
		if err != nil {
			log.Logf("[MITM] Failed to connect to %s: %v", targetAddr, err)
			return err
		}
	}

	defer cc.Close()

	// 捕获请求Body
	if req.Body != nil {
		req.Body = io.NopCloser(io.TeeReader(req.Body, &reqBuf))
	}

	// 转发请求
	if err = req.Write(cc); err != nil {
		log.Logf("[MITM] Failed to write request: %v", err)
		return err
	}

	// 读取响应
	respReader := io.TeeReader(cc, &respBuf)
	resp, err := http.ReadResponse(bufio.NewReader(respReader), req)
	if err != nil {
		log.Logf("[MITM] Failed to read response: %v", err)
		return err
	}
	defer resp.Body.Close()

	// 将响应写回客户端
	if err = resp.Write(rw); err != nil {
		log.Logf("[MITM] Failed to write response: %v", err)
		return err
	}

	// 强制读取Body以触发TeeReader
	if EnableTrafficLog {
		//todo record log
		if resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
		}

		go logMITMTraffic(requestID, clientIP, originReq.Header.Get("proxy_extra_info"), req, resp, &reqBuf, &respBuf)
	}
	return nil
}

// 异步记录MITM流量日志
func logMITMTraffic(requestID, clientIP, extraInfo string, req *http.Request, resp *http.Response, reqBuf, respBuf *limitedBuffer) {
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
		Proto:          "https-mitm",
		ClientIP:       clientIP,
		TargetIP:       req.Host,
		URL:            fmt.Sprintf("https://%s%s", req.Host, req.URL.Path),
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
		requestID, extraInfo, req.Method, req.URL.Path, resp.StatusCode,
		len(reqBody), len(respBody))
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
		go logMITMTraffic(requestID, clientIP, extraInfo, req, resp, reqBuf, respBuf)
	}

	return nil
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
