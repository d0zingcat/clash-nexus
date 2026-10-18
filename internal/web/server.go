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
	"strconv"
	"strings"
	"sync"
	"time"

	"clash-nexus/converter"
	"clash-nexus/converter/clash"
	"clash-nexus/internal/app"
	"clash-nexus/internal/profile"
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
	profiles       *profile.Store
	profileErr     error
}

type cachedSubscription struct {
	result    app.Result
	expiresAt time.Time
}

// NewServer creates a local web/API server.
func NewServer(service *app.Service) *Server {
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return errors.New("redirected to unsupported URL scheme")
			}
			return nil
		},
	}
	if service != nil {
		service.SetClashFetcher(clash.NewDefaultFetcher(client, ""))
	}
	store, storeErr := profile.NewStore()
	return &Server{
		service:        service,
		subscribeCache: map[string]cachedSubscription{},
		client:         client,
		profiles:       store,
		profileErr:     storeErr,
	}
}

// Handler returns all web and API routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/targets", s.targets)
	mux.HandleFunc("GET /api/profiles", s.profileList)
	mux.HandleFunc("POST /api/profiles", s.profileSave)
	mux.HandleFunc("GET /api/profiles/{id}", s.profileGet)
	mux.HandleFunc("PUT /api/profiles/{id}", s.profileSave)
	mux.HandleFunc("DELETE /api/profiles/{id}", s.profileDelete)
	mux.HandleFunc("POST /api/profiles/preview", s.profilePreview)
	mux.HandleFunc("GET /api/profiles/{id}/subscribe", s.profileSubscribe)
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

func (s *Server) profileList(w http.ResponseWriter, r *http.Request) {
	if s.profileErr != nil {
		writeError(w, 500, "storage_error", "profile storage is unavailable")
		return
	}
	items, err := s.profiles.List()
	if err != nil {
		writeError(w, 500, "storage_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"profiles": items})
}
func (s *Server) profileGet(w http.ResponseWriter, r *http.Request) {
	if s.profileErr != nil {
		writeError(w, 500, "storage_error", "profile storage is unavailable")
		return
	}
	p, e := s.profiles.Get(r.PathValue("id"))
	if e != nil {
		writeError(w, 404, "not_found", "profile not found")
		return
	}
	writeJSON(w, 200, p)
}
func (s *Server) profileSave(w http.ResponseWriter, r *http.Request) {
	if s.profileErr != nil {
		writeError(w, 500, "storage_error", "profile storage is unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxInputBytes)
	defer r.Body.Close()
	var p profile.Profile
	if json.NewDecoder(r.Body).Decode(&p) != nil {
		writeError(w, 400, "bad_request", "request body must be a valid profile JSON")
		return
	}
	if r.Method == http.MethodPut {
		p.ID = r.PathValue("id")
	}
	p, err := s.materializeProfile(p)
	if err != nil {
		writeAppError(w, err)
		return
	}
	p, e := s.profiles.Save(p)
	if e != nil {
		writeError(w, 400, "invalid_profile", e.Error())
		return
	}
	writeJSON(w, 200, p)
}
func (s *Server) profileDelete(w http.ResponseWriter, r *http.Request) {
	if s.profileErr != nil {
		writeError(w, 500, "storage_error", "profile storage is unavailable")
		return
	}
	if e := s.profiles.Delete(r.PathValue("id")); e != nil {
		writeError(w, 404, "not_found", "profile not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) materializeProfile(p profile.Profile) (profile.Profile, error) {
	for i := range p.Sources {
		src := &p.Sources[i]
		if strings.TrimSpace(src.URL) != "" {
			b, e := s.fetchRemote(src.URL)
			if e != nil {
				return p, fmt.Errorf("source %q: %w", src.Name, e)
			}
			src.YAML = string(b)
		}
	}
	return p, nil
}
func (s *Server) profilePreview(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxInputBytes)
	defer r.Body.Close()
	var p profile.Profile
	if json.NewDecoder(r.Body).Decode(&p) != nil {
		writeError(w, 400, "bad_request", "request body must be profile JSON")
		return
	}
	p, e := s.materializeProfile(p)
	if e != nil {
		writeAppError(w, e)
		return
	}
	b, e := profile.Compose(p)
	if e != nil {
		writeError(w, 400, "invalid_profile", e.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	_, _ = w.Write(b)
}
func (s *Server) profileSubscribe(w http.ResponseWriter, r *http.Request) {
	if s.profileErr != nil {
		writeError(w, 500, "storage_error", "profile storage is unavailable")
		return
	}
	p, e := s.profiles.Get(r.PathValue("id"))
	if e != nil {
		writeError(w, 404, "not_found", "profile not found")
		return
	}
	if r.URL.Query().Get("token") == "" || r.URL.Query().Get("token") != p.Token {
		writeError(w, 404, "not_found", "subscription not found")
		return
	}
	p, e = s.materializeProfile(p)
	if e != nil {
		writeAppError(w, e)
		return
	}
	b, e := profile.Compose(p)
	if e != nil {
		writeError(w, 500, "invalid_profile", "saved profile can no longer be composed: "+e.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", p.Version))
	w.Header().Set("Content-Disposition", `inline; filename="`+p.ID+`.yaml"`)
	_, _ = w.Write(b)
}

type convertRequest struct {
	Source               string `json:"source"`
	Target               string `json:"target"`
	YAML                 string `json:"yaml"`
	URL                  string `json:"url"`
	QXFinalProxyChain    bool   `json:"qxFinalProxyChain"`
	ExpandProxyProviders bool   `json:"expandProxyProviders"`
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
	s.writeConversion(w, req.Source, req.Target, data, optionsFromRequest(req))
}

func (s *Server) convertFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxInputBytes)
	defer r.Body.Close()

	if err := r.ParseMultipartForm(maxInputBytes); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "file upload is invalid or too large")
		return
	}
	target := strings.TrimSpace(r.FormValue("target"))
	source := strings.TrimSpace(r.FormValue("source"))
	options := optionsFromValues(r.Form)
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
	s.writeConversion(w, source, target, data, options)
}

func (s *Server) subscribe(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	rawURL := strings.TrimSpace(r.URL.Query().Get("url"))
	if target == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "target is required")
		return
	}
	if rawURL == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "url is required")
		return
	}
	options := optionsFromValues(r.URL.Query())

	cacheKey := source + "\x00" + target + "\x00" + rawURL + "\x00" + optionsCacheKey(options)
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
	var result app.Result
	if source == "" || strings.EqualFold(source, "clash") {
		result, err = s.service.ConvertBytesWithOptions(target, data, options)
	} else {
		result, err = s.service.ConvertBytesFromWithOptions(source, target, data, options)
	}
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

func (s *Server) writeConversion(w http.ResponseWriter, source, target string, data []byte, options converter.Options) {
	var result app.Result
	var err error
	if strings.TrimSpace(source) == "" || strings.EqualFold(strings.TrimSpace(source), "clash") {
		result, err = s.service.ConvertBytesWithOptions(strings.TrimSpace(target), data, options)
	} else {
		result, err = s.service.ConvertBytesFromWithOptions(source, strings.TrimSpace(target), data, options)
	}
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

func optionsFromRequest(req convertRequest) converter.Options {
	return converter.Options{
		QXFinalProxyChain:    req.QXFinalProxyChain,
		ExpandProxyProviders: req.ExpandProxyProviders,
	}
}

func optionsFromValues(values url.Values) converter.Options {
	return converter.Options{
		QXFinalProxyChain:    parseBool(values.Get("qx_final_proxy_chain")),
		ExpandProxyProviders: parseBool(values.Get("expand_proxy_providers")),
	}
}

func optionsCacheKey(options converter.Options) string {
	qx := "0"
	if options.QXFinalProxyChain {
		qx = "1"
	}
	expand := "0"
	if options.ExpandProxyProviders {
		expand = "1"
	}
	return "qx_final_proxy_chain=" + qx + "&expand_proxy_providers=" + expand
}

func parseBool(raw string) bool {
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	return err == nil && value
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
	case errors.Is(err, app.ErrUnknownSource), errors.Is(err, app.ErrInvalidLoon), errors.Is(err, app.ErrUnsupportedConversion):
		writeError(w, http.StatusBadRequest, "invalid_conversion", err.Error())
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
