package httpd

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/go-logr/logr"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/a-h/hsts"
	flag "github.com/spf13/pflag"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
	schemeUnix  = "unix"
)

var defaultSchemes []string

func init() {
	defaultSchemes = []string{
		schemeHTTP,
	}
}

// Hook allows for hooking into the lifecycle of the server
type Hook interface {
	ConfigureTLS(*tls.Config)
	ConfigureListener(*http.Server, string, string)
}

var (
	enabledListeners []string
	cleanupTimout    time.Duration
	maxHeaderSize    ByteSize

	DefaultUDSFlags  UnixSocketFlags
	DefaultHTTPFlags HTTPFlags
	DefaultTLSFlags  TLSFlags

	DefaultAdminHandler http.Handler
)

func init() {
	maxHeaderSize = ByteSize(1000000)
	DefaultHTTPFlags.Host = stringEnvOverride(DefaultHTTPFlags.Host, "localhost", "HOST")
	DefaultHTTPFlags.Port = intEnvOverride(DefaultHTTPFlags.Port, 8080, "PORT")
	DefaultTLSFlags.Host = stringEnvOverride(DefaultTLSFlags.Host, "", "TLS_HOST")
	DefaultTLSFlags.Port = intEnvOverride(DefaultTLSFlags.Port, 8443, "TLS_PORT")
	DefaultTLSFlags.Certificate = stringEnvOverride(DefaultTLSFlags.Certificate, "", "TLS_CERTIFICATE")
	DefaultTLSFlags.CertificateKey = stringEnvOverride(DefaultTLSFlags.CertificateKey, "", "TLS_PRIVATE_KEY")
	DefaultTLSFlags.CACertificate = stringEnvOverride(DefaultTLSFlags.CACertificate, "", "TLS_CA_CERTIFICATE")
	DefaultAdminHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// RegisterFlags to the specified pflag set
func RegisterFlags(fs *flag.FlagSet) {
	fs.StringSliceVar(&enabledListeners, "scheme", defaultSchemes, "the listeners to enable, this can be repeated and defaults to the schemes in the swagger spec")
	fs.DurationVar(&cleanupTimout, "cleanup-timeout", 10*time.Second, "grace period for which to wait before shutting down the server")
	fs.Var(&maxHeaderSize, "max-header-size", "controls the maximum number of bytes the server will read parsing the request header's keys and values, including the request line. It does not limit the size of the request body")

	DefaultUDSFlags.RegisterFlags(fs)
	DefaultHTTPFlags.RegisterFlags(fs)
	DefaultTLSFlags.RegisterFlags(fs)
}

func prefixer(prefix string) func(string) string {
	return func(value string) string {
		if prefix == "" {
			return value
		}
		return strings.Join([]string{prefix, value}, "-")
	}
}

func stringEnvOverride(orig string, def string, keys ...string) string {
	for _, k := range keys {
		if os.Getenv(k) != "" {
			return os.Getenv(k)
		}
	}
	if def != "" && orig == "" {
		return def
	}
	return orig
}

func intEnvOverride(orig int, def int, keys ...string) int {
	for _, k := range keys {
		if os.Getenv(k) != "" {
			v, err := strconv.Atoi(os.Getenv(k))
			if err != nil {
				fmt.Fprintln(os.Stderr, k, "is not a valid number")
				os.Exit(1)
			}
			return v
		}
	}
	if def != 0 && orig == 0 {
		return def
	}
	return orig
}

// Option for the server
type Option func(*defaultServer)

// Hooks allows for registering one or more hooks for the server to call during its lifecycle
func Hooks(hook Hook, extra ...Hook) Option {
	h := &compositeHook{
		hooks: append([]Hook{hook}, extra...),
	}
	return func(s *defaultServer) {
		s.callbacks = h
	}
}

type compositeHook struct {
	hooks []Hook
}

func (c *compositeHook) ConfigureTLS(cfg *tls.Config) {
	for _, h := range c.hooks {
		h.ConfigureTLS(cfg)
	}
}

func (c *compositeHook) ConfigureListener(s *http.Server, scheme, addr string) {
	for _, h := range c.hooks {
		h.ConfigureListener(s, scheme, addr)
	}
}

// HandlesRequestsWith handles the http requests to the server
func HandlesRequestsWith(h http.Handler) Option {
	return func(s *defaultServer) {
		s.handler = h
	}
}

// LogsWith provides a logger to the server
func LogsWith(l logr.Logger) Option {
	return func(s *defaultServer) {
		s.logger = l
	}
}

// EnablesSchemes overrides the enabled schemes
func EnablesSchemes(schemes ...string) Option {
	return func(s *defaultServer) {
		s.EnabledListeners = schemes
	}
}

// OnShutdown runs the provided functions on shutdown
func OnShutdown(handlers ...func()) Option {
	return func(s *defaultServer) {
		if len(handlers) == 0 {
			return
		}
		s.onShutdown = func() {
			for _, run := range handlers {
				run()
			}
		}
	}
}

// WithListeners replaces the default listeners with the provided listeres
func WithListeners(listener ServerListener, extra ...ServerListener) Option {
	all := append([]ServerListener{listener}, extra...)
	return func(s *defaultServer) {
		s.listeners = all
	}
}

// WithExtaListeners appends the provided listeners to the default listeners
func WithExtraListeners(listener ServerListener, extra ...ServerListener) Option {
	all := append([]ServerListener{listener}, extra...)
	return func(s *defaultServer) {
		s.listeners = append(s.listeners, all...)
	}
}

// WithAdminListeners configures the listeners for the admin endpoint (like /healthz, /readyz, /metrics)
func WithAdminListeners(listener ServerListener, extra ...ServerListener) Option {
	all := append([]ServerListener{listener}, extra...)
	return func(s *defaultServer) {
		s.adminListeners = append(s.adminListeners, all...)
	}
}

// HandlesAdminWith configures the handler (maybe mux) for the admin endpoint (like /healthz, /readyz, /metrics)
func HandlesAdminWith(handler http.Handler) Option {
	return func(s *defaultServer) {
		s.adminHandler = handler
	}
}

// WithAdminListeners configures the handler and the listeners for the admin endpoint (like /healthz, /readyz, /metrics)
func WithAdmin(handler http.Handler, listener ServerListener, extra ...ServerListener) Option {
	all := append([]ServerListener{listener}, extra...)
	return func(s *defaultServer) {
		s.adminListeners = append(s.adminListeners, all...)
		s.adminHandler = handler
	}
}

func EnableHSTS(maxAge time.Duration, sendPreload bool) Option {
	if maxAge == 0 {
		maxAge = time.Hour * 24 * 126 // 126 days (minimum for inclusion in the Chrome HSTS list)
	}
	return func(s *defaultServer) {
		s.hsts = &hstsConfig{
			MaxAge:      maxAge,
			SendPreload: sendPreload,
		}
	}
}

// New creates a new application server
func New(opts ...Option) Server {
	s := new(defaultServer)

	s.EnabledListeners = enabledListeners
	s.CleanupTimeout = cleanupTimout
	s.MaxHeaderSize = maxHeaderSize
	s.shutdown = make(chan struct{})
	s.interrupt = make(chan os.Signal, 1)
	s.logger = &stdLogger{}
	s.onShutdown = func() {}
	s.listeners = []ServerListener{&DefaultUDSFlags, &DefaultHTTPFlags, &DefaultTLSFlags}
	s.adminHandler = DefaultAdminHandler

	for _, apply := range opts {
		apply(s)
	}

	if s.hsts != nil {
		h := hsts.NewHandler(s.handler)
		h.MaxAge = s.hsts.MaxAge
		h.SendPreloadDirective = s.hsts.SendPreload
		s.handler = h
	}
	return s
}

type hstsConfig struct {
	MaxAge      time.Duration
	SendPreload bool
}

type ServerConfig struct {
	MaxHeaderSize  int
	Logger         logr.Logger
	Handler        http.Handler
	Callbacks      Hook
	CleanupTimeout time.Duration
}

type ServerListener interface {
	Listener() (net.Listener, error)
	Serve(ServerConfig, *sync.WaitGroup) (*http.Server, error)
	Scheme() string
}

// defaultServer for the patmos API
type defaultServer struct {
	EnabledListeners []string
	CleanupTimeout   time.Duration
	MaxHeaderSize    ByteSize

	handler      http.Handler
	adminHandler http.Handler

	shutdown     chan struct{}
	shuttingDown int32
	interrupted  bool
	interrupt    chan os.Signal
	callbacks    Hook
	logger       logr.Logger

	hsts           *hstsConfig
	onShutdown     func()
	listeners      []ServerListener
	adminListeners []ServerListener
}

func (s *defaultServer) hasScheme(scheme string) bool {
	schemes := s.EnabledListeners
	if len(schemes) == 0 {
		schemes = defaultSchemes
	}

	for _, v := range schemes {
		if v == scheme {
			return true
		}
	}
	return false
}

// Serve the api
func (s *defaultServer) Serve() (err error) {
	if err := s.Listen(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	once := new(sync.Once)
	signalNotify(s.interrupt)
	go handleInterrupt(once, s)

	servers := []*http.Server{}
	wg.Add(1)
	go s.handleShutdown(&wg, &servers)

	for _, server := range s.listeners {
		if !s.hasScheme(server.Scheme()) {
			continue
		}
		sc := ServerConfig{
			Callbacks:      s.callbacks,
			CleanupTimeout: s.CleanupTimeout,
			MaxHeaderSize:  int(s.MaxHeaderSize),
			Handler:        s.handler,
			Logger:         s.logger,
		}
		if hs, err := server.Serve(sc, &wg); err == nil {
			servers = append(servers, hs)
		} else {
			return err
		}
	}

	for _, server := range s.adminListeners {
		sc := ServerConfig{
			CleanupTimeout: s.CleanupTimeout,
			MaxHeaderSize:  int(s.MaxHeaderSize),
			Handler:        s.adminHandler,
			Logger:         s.logger,
		}
		if hs, err := server.Serve(sc, &wg); err == nil {
			servers = append(servers, hs)
		} else {
			return err
		}
	}

	wg.Wait()
	return nil
}

// Listen creates the listeners for the server
func (s *defaultServer) Listen() error {
	for _, server := range append(s.listeners, s.adminListeners...) {
		if !s.hasScheme(server.Scheme()) {
			continue
		}
		_, err := server.Listener()
		if err != nil {
			return err
		}
	}
	return nil
}

// Shutdown server and clean up resources
func (s *defaultServer) Shutdown() error {
	if atomic.CompareAndSwapInt32(&s.shuttingDown, 0, 1) {
		close(s.shutdown)
	}
	return nil
}

func (s *defaultServer) handleShutdown(wg *sync.WaitGroup, serversPtr *[]*http.Server) {
	// wg.Done must occur last, after s.api.ServerShutdown()
	// (to preserve old behaviour)
	defer wg.Done()

	<-s.shutdown

	servers := *serversPtr

	ctx, cancel := context.WithTimeout(context.TODO(), 15*time.Second)
	defer cancel()

	shutdownChan := make(chan bool)
	for i := range servers {
		server := servers[i]
		go func() {
			var success bool
			defer func() {
				shutdownChan <- success
			}()
			if err := server.Shutdown(ctx); err != nil {
				// Error from closing listeners, or context timeout:
				s.logger.Error(err, "HTTP server Shutdown.")
			} else {
				success = true
			}
		}()
	}

	// Wait until all listeners have successfully shut down before calling ServerShutdown
	success := true
	for range servers {
		success = success && <-shutdownChan
	}
	if success {
		if s.onShutdown != nil {
			s.onShutdown()
		}
	}
}

// GetHandler returns a handler useful for testing
func (s *defaultServer) GetHandler() http.Handler {
	return s.handler
}

// UnixListener returns the domain socket listener
func (s *defaultServer) UnixListener() (net.Listener, error) {
	if !s.hasScheme(DefaultUDSFlags.Scheme()) {
		return nil, nil
	}
	for _, l := range s.listeners {
		if l.Scheme() == schemeUnix {
			return l.Listener()
		}
	}
	return DefaultUDSFlags.Listener()
}

// HTTPListener returns the http listener
func (s *defaultServer) HTTPListener() (net.Listener, error) {
	if !s.hasScheme(DefaultHTTPFlags.Scheme()) {
		return nil, nil
	}
	for _, l := range s.listeners {
		if l.Scheme() == schemeHTTP {
			return l.Listener()
		}
	}
	return DefaultHTTPFlags.Listener()
}

// TLSListener returns the https listener
func (s *defaultServer) TLSListener() (net.Listener, error) {
	if !s.hasScheme(DefaultTLSFlags.Scheme()) {
		return nil, nil
	}
	for _, l := range s.listeners {
		if l.Scheme() == schemeHTTPS {
			return l.Listener()
		}
	}
	return DefaultTLSFlags.Listener()
}

func handleInterrupt(once *sync.Once, s *defaultServer) {
	once.Do(func() {
		for range s.interrupt {
			if s.interrupted {
				continue
			}
			s.logger.Info("Shutting down... ")
			s.interrupted = true
			if err := s.Shutdown(); err != nil {
				s.logger.Error(err, "error during server shutdown.")
			}
		}
	})
}

func signalNotify(interrupt chan<- os.Signal) {
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
}

// Server is the interface a server implements
type Server interface {
	GetHandler() http.Handler

	TLSListener() (net.Listener, error)
	HTTPListener() (net.Listener, error)
	UnixListener() (net.Listener, error)

	Listen() error
	Serve() error
	Shutdown() error
}

type stdLogger struct {
}

func (s *stdLogger) Info(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (s *stdLogger) Error(err error, format string, args ...interface{}) {
	log.Fatalf(format, args...)
}

func (s *stdLogger) V(level int) logr.InfoLogger {
	return s
}

func (s *stdLogger) Enabled() bool { return true }
func (s *stdLogger) WithValues(keysAndValues ...interface{}) logr.Logger {
	// not used so just returns self
	return s
}
func (s *stdLogger) WithName(name string) logr.Logger {
	// not used so just returns self
	return s
}

// SplitHostPort splits a network address into a host and a port.
// The port is -1 when there is no port to be found
func SplitHostPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", -1, err
	}
	if p == "" {
		return "", -1, &net.AddrError{Err: "missing port in address", Addr: addr}
	}

	pi, err := strconv.Atoi(p)
	if err != nil {
		return "", -1, err
	}
	return h, pi, nil
}
