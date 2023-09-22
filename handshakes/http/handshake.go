package http

import (
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/stanford-esrg/lzr"
)

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

func (h *HandshakeMod) GetData(dst string) []byte {

	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = dst
	req.Header.Add("Host", dst)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36 Edg/114.0.1823.43")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip")
	data, _ := httputil.DumpRequest(req, false)
	return data
}

func (h *HandshakeMod) Verify(data string) string {

	if !strings.Contains(data, "HTTPS") &&
		(strings.Contains(data, "HTTP") || strings.Contains(data, "html") ||
			strings.Contains(data, "HTML") || strings.Contains(data, "<h1>")) {
		return "http"
	}
	return ""

}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("http", &h)
}
