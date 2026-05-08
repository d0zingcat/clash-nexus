// Package web provides the embedded local web UI and conversion API.
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"clash-nexus/internal/app"
)

const (
	maxInputBytes = 5 * 1024 * 1024
	subscribeTTL  = 10 * time.Minute
)

//go:embed static/*
var staticFS embed.FS

// Server wires the conversion service into HTTP handlers.
type Server struct {
	service        *app.Service
	client         *http.Client
	subscribeCache map[string]cachedSubscription
	cacheMu        sync.Mutex
}

type cachedSubscription struct {
	result    app.Result
	expiresAt time.Time
}

// NewServer creates a local web/API server.
func NewServer(service *app.Service) *Server {
	return &Server{
		service:        service,
		subscribeCache: map[string]cachedSubscription{},
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return errors.New("redirected to unsupported URL scheme")
				}
				return nil
			},
		},
	}
}

// Handler returns all web and API routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/targets", s.targets)
	mux.HandleFunc("POST /api/convert", s.convertJSON)
	mux.HandleFunc("POST /api/convert/file", s.convertFile)
	mux.HandleFunc("GET /api/subscribe", s.subscribe)
	mux.Handle("GET /static/", http.FileServer(http.FS(staticFS)))
	return mux
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, staticFS, "static/index.html")
}

func (s *Server) targets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"targets": s.service.Targets()})
}

type convertRequest struct {
	Target string `json:"target"`
	YAML   string `json:"yaml"`
	URL    string `json:"url"`
}

func (s *Server) convertJSON(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxInputBytes)
	defer r.Body.Close()

	var req convertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "request body must be JSON")
		return
	}

	data, err := s.requestData(req)
	if err != nil {
		writeAppError(w, err)
		return
	}
	s.writeConversion(w, req.Target, data)
}

func (s *Server) convertFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxInputBytes)
	defer r.Body.Close()

	if err := r.ParseMultipartForm(maxInputBytes); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "file upload is invalid or too large")
		return
	}
	target := strings.TrimSpace(r.FormValue("target"))
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "file is required")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxInputBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "failed to read uploaded file")
		return
	}
	if len(data) > maxInputBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "input must be 5 MiB or smaller")
		return
	}
	s.writeConversion(w, target, data)
}

func (s *Server) subscribe(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	rawURL := strings.TrimSpace(r.URL.Query().Get("url"))
	if target == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "target is required")
		return
	}
	if rawURL == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "url is required")
		return
	}

	cacheKey := target + "\x00" + rawURL
	if result, ok := s.getCachedSubscription(cacheKey); ok {
		w.Header().Set("X-Clash-Nexus-Cache", "HIT")
		writeSubscription(w, result)
		return
	}

	data, err := s.fetchRemote(rawURL)
	if err != nil {
		writeAppError(w, err)
		return
	}
	result, err := s.service.ConvertBytes(target, data)
	if err != nil {
		writeAppError(w, err)
		return
	}
	s.setCachedSubscription(cacheKey, result)

	w.Header().Set("X-Clash-Nexus-Cache", "MISS")
	writeSubscription(w, result)
}

func (s *Server) getCachedSubscription(key string) (app.Result, bool) {
	now := time.Now()
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	cached, ok := s.subscribeCache[key]
	if !ok {
		return app.Result{}, false
	}
	if now.After(cached.expiresAt) {
		delete(s.subscribeCache, key)
		return app.Result{}, false
	}
	return cached.result, true
}

func (s *Server) setCachedSubscription(key string, result app.Result) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.subscribeCache[key] = cachedSubscription{
		result:    result,
		expiresAt: time.Now().Add(subscribeTTL),
	}
}

func writeSubscription(w http.ResponseWriter, result app.Result) {
	if result.Extension == ".yaml" || result.Extension == ".yml" {
		w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Content-Disposition", `inline; filename="`+result.Filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.Content)
}

func (s *Server) requestData(req convertRequest) ([]byte, error) {
	target := strings.TrimSpace(req.Target)
	if target == "" {
		return nil, httpError{status: http.StatusBadRequest, code: "bad_request", message: "target is required"}
	}
	yamlText := strings.TrimSpace(req.YAML)
	rawURL := strings.TrimSpace(req.URL)
	switch {
	case yamlText != "" && rawURL != "":
		return nil, httpError{status: http.StatusBadRequest, code: "bad_request", message: "provide either yaml or url, not both"}
	case yamlText != "":
		if len([]byte(req.YAML)) > maxInputBytes {
			return nil, httpError{status: http.StatusRequestEntityTooLarge, code: "too_large", message: "input must be 5 MiB or smaller"}
		}
		return []byte(req.YAML), nil
	case rawURL != "":
		return s.fetchRemote(rawURL)
	default:
		return nil, httpError{status: http.StatusBadRequest, code: "bad_request", message: "yaml or url is required"}
	}
}

func (s *Server) fetchRemote(raw string) ([]byte, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, httpError{status: http.StatusBadRequest, code: "bad_url", message: "url is invalid"}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, httpError{status: http.StatusBadRequest, code: "bad_url", message: "url must use http or https"}
	}

	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, httpError{status: http.StatusBadRequest, code: "bad_url", message: "url is invalid"}
	}
	req.Header.Set("User-Agent", "clash-nexus/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, httpError{status: http.StatusBadGateway, code: "fetch_failed", message: fmt.Sprintf("failed to fetch url: %v", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, httpError{status: http.StatusBadGateway, code: "fetch_failed", message: fmt.Sprintf("url returned HTTP %d", resp.StatusCode)}
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxInputBytes+1))
	if err != nil {
		return nil, httpError{status: http.StatusBadGateway, code: "fetch_failed", message: "failed to read url response"}
	}
	if len(data) > maxInputBytes {
		return nil, httpError{status: http.StatusRequestEntityTooLarge, code: "too_large", message: "remote input must be 5 MiB or smaller"}
	}
	return data, nil
}

func (s *Server) writeConversion(w http.ResponseWriter, target string, data []byte) {
	result, err := s.service.ConvertBytes(strings.TrimSpace(target), data)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":    result.Target,
		"filename":  result.Filename,
		"extension": result.Extension,
		"content":   string(result.Content),
		"warnings":  result.Warnings,
	})
}

type httpError struct {
	status  int
	code    string
	message string
}

func (e httpError) Error() string { return e.message }

func writeAppError(w http.ResponseWriter, err error) {
	var hErr httpError
	if errors.As(err, &hErr) {
		writeError(w, hErr.status, hErr.code, hErr.message)
		return
	}
	switch {
	case errors.Is(err, app.ErrUnknownTarget):
		writeError(w, http.StatusBadRequest, "unknown_target", err.Error())
	case errors.Is(err, app.ErrInvalidYAML):
		writeError(w, http.StatusBadRequest, "invalid_yaml", err.Error())
	case errors.Is(err, app.ErrConvertFailed):
		writeError(w, http.StatusInternalServerError, "conversion_failed", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ListenAndServe starts the local web server.
func ListenAndServe(addr string, service *app.Service) error {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("invalid addr %q: %w", addr, err)
	}
	return http.ListenAndServe(addr, NewServer(service).Handler())
}
