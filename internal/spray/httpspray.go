package spray

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
)

// sprayPaths are ranked HTTP endpoints for credential validation. The top
// entries give a clean 200/401 oracle and lean on legacy auth.
var sprayPaths = []string{
	"/EWS/Exchange.asmx", "/Microsoft-Server-ActiveSync/",
	"/Autodiscover/Autodiscover.xml", "/mapi/emsmdb/", "/rpc/", "/OAB/", "/owa/",
}

const userAgent = "Mozilla/5.0 (ntlmscout)"

var reNTLMTok = regexp.MustCompile(`NTLM ([A-Za-z0-9+/=]+)`)

// noStatus signals that no clean HTTP response was obtained (Python's None).
const noStatus = -1

func writeReq(conn net.Conn, method, path, host string, hdrs map[string]string, timeout time.Duration) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	for k, v := range hdrs {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write([]byte(b.String()))
	return err
}

func readResp(conn net.Conn, br *bufio.Reader, timeout time.Duration) (*http.Response, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	return http.ReadResponse(br, nil)
}

// SprayNTLM runs a full NTLM Type-1/2/3 exchange over one keep-alive
// connection. It returns the HTTP status of the Type-3 response, or noStatus.
func (r *Runner) sprayNTLM(host string, port int, useTLS bool, path, domain, user, password string) int {
	conn, err := r.cfg.Connect(host, port, useTLS, r.timeout)
	if err != nil {
		r.cfg.Debugf("spray_ntlm "+host, err)
		return noStatus
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	t1 := base64.StdEncoding.EncodeToString(ntlm.DefaultType1())
	if err := writeReq(conn, "GET", path, host, map[string]string{
		"Authorization": "NTLM " + t1, "User-Agent": userAgent, "Connection": "keep-alive",
	}, r.timeout); err != nil {
		return noStatus
	}
	resp1, err := readResp(conn, br, r.timeout)
	if err != nil {
		r.cfg.Debugf("spray_ntlm resp1 "+host, err)
		return noStatus
	}
	tok := findNTLMToken(resp1.Header)
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if tok == "" {
		return noStatus // NTLM not offered here
	}
	t2, err := base64.StdEncoding.DecodeString(tok)
	if err != nil || len(t2) < 48 {
		return noStatus
	}
	serverChallenge := t2[24:32]
	tiLen := int(binary.LittleEndian.Uint16(t2[40:42]))
	tiOff := int(binary.LittleEndian.Uint32(t2[44:48]))
	if tiOff+tiLen > len(t2) {
		return noStatus
	}
	targetInfo := t2[tiOff : tiOff+tiLen]
	ntV2 := ntowfv2(password, user, domain)
	ntResp := ntlmv2Response(ntV2, serverChallenge, targetInfo)
	t3 := base64.StdEncoding.EncodeToString(ntlm.BuildType3(domain, user, ntResp, ""))

	if err := writeReq(conn, "GET", path, host, map[string]string{
		"Authorization": "NTLM " + t3, "User-Agent": userAgent, "Connection": "keep-alive",
	}, r.timeout); err != nil {
		return noStatus
	}
	resp2, err := readResp(conn, br, r.timeout)
	if err != nil {
		r.cfg.Debugf("spray_ntlm resp2 "+host, err)
		return noStatus
	}
	status := resp2.StatusCode
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	return status
}

func (r *Runner) sprayBasic(host string, port int, useTLS bool, path, user, password string) int {
	conn, err := r.cfg.Connect(host, port, useTLS, r.timeout)
	if err != nil {
		r.cfg.Debugf("spray_basic "+host, err)
		return noStatus
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
	if err := writeReq(conn, "GET", path, host, map[string]string{
		"Authorization": "Basic " + cred, "User-Agent": userAgent,
	}, r.timeout); err != nil {
		return noStatus
	}
	resp, err := readResp(conn, br, r.timeout)
	if err != nil {
		return noStatus
	}
	status := resp.StatusCode
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return status
}

func findNTLMToken(h http.Header) string {
	for _, v := range h.Values("WWW-Authenticate") {
		if m := reNTLMTok.FindStringSubmatch(v); m != nil {
			return m[1]
		}
	}
	return ""
}

// learnDomain sends a Type-1 and reads the NetBIOS domain from the Type-2.
func (r *Runner) learnDomain(host string, port int, useTLS bool, path string) string {
	conn, err := r.cfg.Connect(host, port, useTLS, r.timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	t1 := base64.StdEncoding.EncodeToString(ntlm.DefaultType1())
	if err := writeReq(conn, "GET", path, host, map[string]string{
		"Authorization": "NTLM " + t1, "User-Agent": "Mozilla/5.0",
	}, r.timeout); err != nil {
		return ""
	}
	resp, err := readResp(conn, br, r.timeout)
	if err != nil {
		return ""
	}
	tok := findNTLMToken(resp.Header)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if tok == "" {
		return ""
	}
	blob, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		return ""
	}
	parsed, err := ntlm.ParseChallenge(blob)
	if err != nil || parsed.TargetInfo == nil {
		return ""
	}
	return parsed.TargetInfo.NbDomainName
}

// pickEndpoint returns the first endpoint offering the needed auth scheme,
// probing unauthenticated and reading the 401's WWW-Authenticate list.
func (r *Runner) pickEndpoint(host string, port int, useTLS bool, forcedPath string) (path, domain string) {
	wanted := []string{"ntlm", "negotiate"}
	if r.auth == "basic" {
		wanted = []string{"basic"}
	}
	paths := sprayPaths
	if forcedPath != "" {
		paths = []string{forcedPath}
	}
	for _, p := range paths {
		conn, err := r.cfg.Connect(host, port, useTLS, r.timeout)
		if err != nil {
			continue
		}
		br := bufio.NewReader(conn)
		if err := writeReq(conn, "GET", p, host, map[string]string{"User-Agent": "Mozilla/5.0"}, r.timeout); err != nil {
			conn.Close()
			continue
		}
		resp, err := readResp(conn, br, r.timeout)
		if err != nil {
			conn.Close()
			continue
		}
		auths := strings.ToLower(strings.Join(resp.Header.Values("WWW-Authenticate"), " "))
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		conn.Close()
		for _, w := range wanted {
			if strings.Contains(auths, w) {
				d := ""
				if r.auth != "basic" {
					d = r.learnDomain(host, port, useTLS, p)
				}
				return p, d
			}
		}
	}
	if forcedPath != "" {
		return forcedPath, ""
	}
	return "", ""
}

// targetParts derives (host, port, useTLS, path) from a bare host or URL.
func targetParts(t string) (host string, port int, useTLS bool, path string) {
	if strings.Contains(t, "://") {
		scheme, rest, _ := strings.Cut(t, "://")
		scheme = strings.ToLower(scheme)
		hostport, _, _ := strings.Cut(rest, "/")
		host, port = splitHostPort(hostport)
		if port == 0 {
			if scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
		path = rest[len(hostport):]
		return host, port, scheme == "https", path
	}
	host, port = splitHostPort(t)
	if port == 0 {
		port = 443
	}
	return host, port, port != 80, ""
}

// identity resolves how to present a username: (sendDomain, sendUser, display).
func identity(user, domain string) (string, string, string) {
	if strings.Contains(user, "@") {
		return "", user, user
	}
	if strings.Contains(user, "\\") {
		d, u, _ := strings.Cut(user, "\\")
		return d, u, user
	}
	if domain != "" {
		return domain, user, domain + "\\" + user
	}
	return "", user, user
}

func splitHostPort(token string) (string, int) {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(token, "[") {
		host, rest, _ := strings.Cut(token[1:], "]")
		if strings.HasPrefix(rest, ":") {
			if p, err := strconv.Atoi(rest[1:]); err == nil {
				return host, p
			}
		}
		return host, 0
	}
	if strings.Count(token, ":") == 1 {
		h, p, _ := strings.Cut(token, ":")
		if n, err := strconv.Atoi(p); err == nil {
			return h, n
		}
		return token, 0
	}
	return token, 0
}

var _ = netx.Config{}
