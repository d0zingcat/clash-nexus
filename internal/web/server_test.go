package web

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"clash-nexus/internal/app"
)

const testConfig = `
proxies:
  - name: direct-ss
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - direct-ss
rules:
  - MATCH,Proxy
`

func TestTargets(t *testing.T) {
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/targets")
	if err != nil {
		t.Fatalf("GET /api/targets error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		Targets []app.Target `json:"targets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Targets) != 3 {
		t.Fatalf("targets = %#v, want 3 targets", body.Targets)
	}
}

func TestConvertJSONYAML(t *testing.T) {
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/api/convert", map[string]string{
		"target": "loon",
		"yaml":   testConfig,
	})
	defer resp.Body.Close()
	assertConverted(t, resp, "loon")
}

func TestConvertJSONURL(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, testConfig)
	}))
	defer remote.Close()
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/api/convert", map[string]string{
		"target": "egern",
		"url":    remote.URL,
	})
	defer resp.Body.Close()
	assertConverted(t, resp, "egern")
}

func TestConvertJSONReturnsWarnings(t *testing.T) {
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/api/convert", map[string]string{
		"target": "egern",
		"yaml": `
rule-providers:
  Tencent:
    url: https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Tencent.yaml
rules:
  - RULE-SET,Tencent,DIRECT
  - MATCH,Proxy
`,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusOK, data)
	}

	var body struct {
		Warnings []string `json:"warnings"`
		Content  string   `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Warnings) != 1 || !strings.Contains(body.Warnings[0], "blackmatrix7") {
		t.Fatalf("warnings = %#v, want blackmatrix7 warning", body.Warnings)
	}
	if strings.Contains(body.Content, "ACL4SSR") {
		t.Fatalf("content still contains skipped ACL4SSR rule-set: %s", body.Content)
	}
}

func TestConvertJSONQXFinalProxyChainOption(t *testing.T) {
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	disabled := postJSON(t, ts.URL+"/api/convert", map[string]interface{}{
		"target": "qx",
		"yaml":   testConfig,
	})
	defer disabled.Body.Close()
	disabledBody := readConvertBody(t, disabled)
	if strings.Contains(disabledBody.Content, "final, proxy, via-interface=%TUN%") {
		t.Fatalf("disabled option unexpectedly added via-interface: %s", disabledBody.Content)
	}

	enabled := postJSON(t, ts.URL+"/api/convert", map[string]interface{}{
		"target":            "qx",
		"yaml":              testConfig,
		"qxFinalProxyChain": true,
	})
	defer enabled.Body.Close()
	enabledBody := readConvertBody(t, enabled)
	if !strings.Contains(enabledBody.Content, "final, proxy, via-interface=%TUN%") {
		t.Fatalf("enabled option did not add via-interface: %s", enabledBody.Content)
	}
}

func TestSubscribe(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, testConfig)
	}))
	defer remote.Close()
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/subscribe?target=loon&url="+urlQueryEscape(remote.URL), nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET subscribe error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusOK, data)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !strings.Contains(string(data), "[General]") {
		t.Fatalf("subscription body does not look like Loon config: %s", data)
	}
}

func TestSubscribeQXFinalProxyChainOptionAffectsCache(t *testing.T) {
	requests := 0
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = io.WriteString(w, testConfig)
	}))
	defer remote.Close()
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	baseEndpoint := ts.URL + "/api/subscribe?target=qx&url=" + urlQueryEscape(remote.URL)
	disabledResp, err := http.Get(baseEndpoint)
	if err != nil {
		t.Fatalf("disabled GET subscribe error = %v", err)
	}
	disabledBody, _ := io.ReadAll(disabledResp.Body)
	_ = disabledResp.Body.Close()
	if disabledResp.StatusCode != http.StatusOK {
		t.Fatalf("disabled status = %d, want %d", disabledResp.StatusCode, http.StatusOK)
	}
	if strings.Contains(string(disabledBody), "final, proxy, via-interface=%TUN%") {
		t.Fatalf("disabled subscription unexpectedly added via-interface: %s", disabledBody)
	}

	enabledResp, err := http.Get(baseEndpoint + "&qx_final_proxy_chain=1")
	if err != nil {
		t.Fatalf("enabled GET subscribe error = %v", err)
	}
	enabledBody, _ := io.ReadAll(enabledResp.Body)
	_ = enabledResp.Body.Close()
	if enabledResp.StatusCode != http.StatusOK {
		t.Fatalf("enabled status = %d, want %d", enabledResp.StatusCode, http.StatusOK)
	}
	if !strings.Contains(string(enabledBody), "final, proxy, via-interface=%TUN%") {
		t.Fatalf("enabled subscription did not add via-interface: %s", enabledBody)
	}
	if requests != 2 {
		t.Fatalf("remote requests = %d, want 2 distinct cache keys", requests)
	}
}

func TestSubscribeCachesSuccessfulConversion(t *testing.T) {
	requests := 0
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = io.WriteString(w, strings.ReplaceAll(testConfig, "direct-ss", "direct-ss-"+strconv.Itoa(requests)))
	}))
	defer remote.Close()
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	endpoint := ts.URL + "/api/subscribe?target=loon&url=" + urlQueryEscape(remote.URL)
	firstResp, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("first GET subscribe error = %v", err)
	}
	firstBody, _ := io.ReadAll(firstResp.Body)
	_ = firstResp.Body.Close()
	if firstResp.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want %d", firstResp.StatusCode, http.StatusOK)
	}
	if firstResp.Header.Get("X-Clash-Nexus-Cache") != "MISS" {
		t.Fatalf("first cache header = %q, want MISS", firstResp.Header.Get("X-Clash-Nexus-Cache"))
	}

	secondResp, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("second GET subscribe error = %v", err)
	}
	secondBody, _ := io.ReadAll(secondResp.Body)
	_ = secondResp.Body.Close()
	if secondResp.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d, want %d", secondResp.StatusCode, http.StatusOK)
	}
	if secondResp.Header.Get("X-Clash-Nexus-Cache") != "HIT" {
		t.Fatalf("second cache header = %q, want HIT", secondResp.Header.Get("X-Clash-Nexus-Cache"))
	}
	if requests != 1 {
		t.Fatalf("remote requests = %d, want 1", requests)
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatal("cached response body differs from first response")
	}
}

func TestConvertFile(t *testing.T) {
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("target", "loon")
	part, err := writer.CreateFormFile("file", "config.yaml")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	_, _ = part.Write([]byte(testConfig))
	_ = writer.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/convert/file", &body)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST file error = %v", err)
	}
	defer resp.Body.Close()
	assertConverted(t, resp, "loon")
}

func TestConvertRejectsBadURLScheme(t *testing.T) {
	ts := httptest.NewServer(NewServer(app.NewService()).Handler())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/api/convert", map[string]string{
		"target": "loon",
		"url":    "file:///tmp/config.yaml",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func urlQueryEscape(raw string) string {
	replacer := strings.NewReplacer(":", "%3A", "/", "%2F")
	return replacer.Replace(raw)
}

func postJSON(t *testing.T, endpoint string, payload interface{}) *http.Response {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST error = %v", err)
	}
	return resp
}

func assertConverted(t *testing.T, resp *http.Response, target string) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusOK, data)
	}
	var body struct {
		Target  string `json:"target"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Target != target {
		t.Fatalf("target = %q, want %q", body.Target, target)
	}
	if strings.TrimSpace(body.Content) == "" {
		t.Fatal("content is empty")
	}
}

type convertBody struct {
	Target  string `json:"target"`
	Content string `json:"content"`
}

func readConvertBody(t *testing.T, resp *http.Response) convertBody {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusOK, data)
	}
	var body convertBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.TrimSpace(body.Content) == "" {
		t.Fatal("content is empty")
	}
	return body
}
