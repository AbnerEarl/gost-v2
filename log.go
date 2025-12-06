package gost

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// LogLogger uses the standard log package as the logger
type LogLogger struct {
}

// Log uses the standard log library log.Output
func (l *LogLogger) Log(v ...interface{}) {
	log.Output(3, fmt.Sprintln(v...))
}

// Logf uses the standard log library log.Output
func (l *LogLogger) Logf(format string, v ...interface{}) {
	log.Output(3, fmt.Sprintf(format, v...))
}

// NopLogger is a dummy logger that discards the log outputs
type NopLogger struct {
}

// Log does nothing
func (l *NopLogger) Log(v ...interface{}) {
}

// Logf does nothing
func (l *NopLogger) Logf(format string, v ...interface{}) {
}

// limitedBuffer 将最多保存 N 字节，用于记录 body 的前缀
type limitedBuffer struct {
	buf    bytes.Buffer
	limit  int
	locked sync.Mutex
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.locked.Lock()
	defer b.locked.Unlock()
	if b.limit <= 0 {
		return len(p), nil // 不保存，只用于吞吐
	}
	n := len(p)
	remain := b.limit - b.buf.Len()
	if remain > 0 {
		toWrite := p
		if len(p) > remain {
			toWrite = p[:remain]
		}
		b.buf.Write(toWrite)
	}
	return n, nil
}

func (b *limitedBuffer) Bytes() []byte {
	b.locked.Lock()
	defer b.locked.Unlock()
	return b.buf.Bytes()
}

// TrafficLog 表示一条流量日志记录。序列化为 JSON（单行）后便于 ELK/Fluentd 等系统采集。
type TrafficLog struct {
	// 基本信息
	ID       string    `json:"id"`          // 唯一请求 ID（UUID）
	Time     time.Time `json:"time"`        // 记录时间点（RFC3339）
	Proto    string    `json:"proto"`       // 协议类型："http" / "https" / "socks5"
	Duration int64     `json:"duration_ms"` // 请求处理耗时（毫秒），如未知可为 0

	// 客户端信息
	ClientIP   string `json:"client_ip,omitempty"`
	ClientPort int    `json:"client_port,omitempty"`

	// 目标信息
	TargetHost string `json:"target_host,omitempty"` // 客户端给出的 host（如 CONNECT 的 host:port 或 HTTP 请求的 Host）
	TargetIP   string `json:"target_ip,omitempty"`   // 实际 dial 出的目标 IP（如果可用）
	TargetPort int    `json:"target_port,omitempty"`

	// HTTP 相关（若非 HTTP 协议可为空）
	Method string `json:"method,omitempty"` // GET/POST/...
	URL    string `json:"url,omitempty"`    // 完整 URL（明文 HTTP 情况可见；HTTPS 默认为空，除非 MITM）
	Query  string `json:"query,omitempty"`  // 完整 URL（明文 HTTP 情况可见；HTTPS 默认为空，除非 MITM）

	// 请求与响应状态
	Status    int `json:"status,omitempty"`     // 响应状态码（HTTP），非 HTTP 可留空
	ReqBytes  int `json:"req_bytes,omitempty"`  // 客户端 -> 目标 总字节数（如果能测到）
	RespBytes int `json:"resp_bytes,omitempty"` // 目标 -> 客户端 总字节数（如果能测到）

	// Headers（保留原始 header map，写入日志前可调用 RedactHeaders 掩码敏感字段）
	ReqHeaders  http.Header `json:"req_headers,omitempty"`
	RespHeaders http.Header `json:"resp_headers,omitempty"`

	// Body preview（只保留前缀片段）——采用 base64 编码以安全保存任意二进制数据
	ReqBodyBase64  string `json:"req_body_base64,omitempty"`
	ReqBodyTrunc   bool   `json:"req_body_truncated,omitempty"`
	RespBodyBase64 string `json:"resp_body_base64,omitempty"`
	RespBodyTrunc  bool   `json:"resp_body_truncated,omitempty"`

	// 其他可选元数据
	Notes map[string]interface{} `json:"notes,omitempty"`
}

// RedactHeaders 对 header map 中指定的 headerName 列表进行掩码（替换为 "<redacted>"）
// headerNames 可传 "Authorization","Cookie" 等不区分大小写
func (t *TrafficLog) RedactHeaders(headerNames []string) {
	if t == nil || len(headerNames) == 0 {
		return
	}
	// build lowercase set
	set := map[string]struct{}{}
	for _, h := range headerNames {
		set[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	redact := func(h http.Header) {
		if h == nil {
			return
		}
		for k := range h {
			if _, ok := set[strings.ToLower(k)]; ok {
				h[k] = []string{"<redacted>"}
			}
		}
	}
	redact(t.ReqHeaders)
	redact(t.RespHeaders)
}

// encodeBodyPreview 把 body bytes 转成 base64 preview，并根据 limit 标注是否被截断
// limit == 0 表示不保存 body
func encodeBodyPreview(body []byte, limit int) (base64str string, truncated bool) {
	if limit <= 0 || len(body) == 0 {
		return "", false
	}
	if len(body) > limit {
		truncated = true
		body = body[:limit]
	}
	base64str = base64.StdEncoding.EncodeToString(body)
	return base64str, truncated
}

// Helper: 从 net.Addr 提取 ip 和 port（失败则返回 empty / 0）
func addrToIPPort(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		// 有可能 addr.String 不是 host:port（极少数情况），尝试作为 host 返回
		return addr.String(), 0
	}
	port := 0
	if p, err := strconv.Atoi(portStr); err == nil {
		port = p
	}
	return host, port
}

// ToJSON 将 TrafficLog 序列化为单行 JSON（便于日志系统消费）
func (t *TrafficLog) ToJSON() ([]byte, error) {
	// 为了输出控制，可以在这里对某些字段做最终处理（比如截断 notes）
	return json.Marshal(t)
}

func Write(t *TrafficLog) {
	log.Printf("[traffic] %s %s %s -> %s code=%d req=%q resp=%q\n",
		t.Proto, t.ClientIP, t.URL, t.TargetIP, t.Status,
		t.RespBodyBase64, t.RespBodyBase64)
}
