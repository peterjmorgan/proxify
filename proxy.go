package proxify

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/martian/v3"
	martianlog "github.com/projectdiscovery/martian/v3/log"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/logger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
	rbtransport "github.com/projectdiscovery/roundrobin/transport"
	"github.com/projectdiscovery/tinydns"
	errorutil "github.com/projectdiscovery/utils/errors"
	readerUtil "github.com/projectdiscovery/utils/reader"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/things-go/go-socks5"
)

type OnRequestFunc func(req *http.Request, ctx *FlowContext) error
type OnResponseFunc func(resp *http.Response, ctx *FlowContext) error

type Options struct {
	DumpRequest                 bool
	DumpResponse                bool
	OutputJsonl                 bool
	MaxSize                     int
	Verbosity                   types.Verbosity
	CertCacheSize               int
	Directory                   string
	ListenAddrHTTP              string
	ListenAddrSocks5            string
	OutputDirectory             string
	OutputFile                  string
	OutputFormat                string
	RequestDSL                  []string
	ResponseDSL                 []string
	UpstreamHTTPProxies         []string
	UpstreamSock5Proxies        []string
	ListenDNSAddr               string
	DNSMapping                  string
	DNSFallbackResolver         string
	RequestMatchReplaceDSL      []string
	ResponseMatchReplaceDSL     []string
	OnRequestCallback           OnRequestFunc
	OnResponseCallback          OnResponseFunc
	Deny                        []string
	Allow                       []string
	PassThrough                 []string
	UpstreamProxyRequestsNumber int
	Elastic                     *elastic.Options
	Kafka                       *kafka.Options
	// TLS Fingerprinting
	TLSFingerprint              bool
	TLSProfile                  string
}

type Proxy struct {
	Dialer       *fastdialer.Dialer
	options      *Options
	logger       *logger.Logger
	httpProxy    *martian.Proxy
	socks5proxy  *socks5.Server
	socks5tunnel *superproxy.SuperProxy
	bufioPool    *bufiopool.Pool
	tinydns      *tinydns.TinyDNS
	rbhttp       *rbtransport.RoundTransport
	rbsocks5     *rbtransport.RoundTransport
	proxifyMux   *http.ServeMux // serve banner page and static files
	listenAddr   string

	// Candidate serving core (migration plan Step P10). adapter is the default
	// serving engine (mitmproxy-go fork); transport is the single owned upstream
	// RoundTripper it dials origins through. httpServer, httpListener, and
	// socksListener plus the run context/cancel and waitgroup are the serving
	// resources Run owns and Stop will release once P16 completes shutdown.
	adapter       *mitmproxyAdapter
	transport     http.RoundTripper
	httpServer    *http.Server
	httpListener  net.Listener
	socksListener net.Listener
	runCtx        context.Context
	runCancel     context.CancelFunc
	wg            sync.WaitGroup
}

func NewProxy(options *Options) (*Proxy, error) {

	switch options.Verbosity {
	case types.VerbositySilent:
		martianlog.SetLevel(martianlog.Silent)
	case types.VerbosityVerbose:
		martianlog.SetLevel(martianlog.Info)
	case types.VerbosityVeryVerbose:
		martianlog.SetLevel(martianlog.Debug)
	default:
		martianlog.SetLevel(martianlog.Error)
	}

	logger := logger.NewLogger(&logger.OptionsLogger{
		Verbosity:    options.Verbosity,
		OutputFile:   options.OutputFile,
		OutputFormat: options.OutputFormat,
		OutputFolder: options.OutputDirectory,
		DumpRequest:  options.DumpRequest,
		DumpResponse: options.DumpResponse,
		MaxSize:      options.MaxSize,
		Elastic:      options.Elastic,
		Kafka:        options.Kafka,
	})

	var tdns *tinydns.TinyDNS

	fastdialerOptions := fastdialer.DefaultOptions
	fastdialerOptions.EnableFallback = true
	fastdialerOptions.Deny = options.Deny
	fastdialerOptions.Allow = options.Allow
	if options.ListenDNSAddr != "" {
		dnsmapping := make(map[string]*tinydns.DnsRecord)
		for _, record := range strings.Split(options.DNSMapping, ",") {
			data := strings.Split(record, ":")
			if len(data) != 2 {
				continue
			}
			dnsmapping[data[0]] = &tinydns.DnsRecord{A: []string{data[1]}}
		}
		var err error
		tdns, err = tinydns.New(&tinydns.Options{
			ListenAddress:   options.ListenDNSAddr,
			Net:             "udp",
			UpstreamServers: []string{options.DNSFallbackResolver},
			DnsRecords:      dnsmapping,
		})
		if err != nil {
			return nil, err
		}
		fastdialerOptions.BaseResolvers = []string{"127.0.0.1" + options.ListenDNSAddr}
	}
	dialer, err := fastdialer.NewDialer(fastdialerOptions)
	if err != nil {
		return nil, err
	}

	var rbhttp, rbsocks5 *rbtransport.RoundTransport
	if len(options.UpstreamHTTPProxies) > 0 {
		rbhttp, err = rbtransport.NewWithOptions(options.UpstreamProxyRequestsNumber, options.UpstreamHTTPProxies...)
		if err != nil {
			return nil, err
		}
	}
	if len(options.UpstreamSock5Proxies) > 0 {
		rbsocks5, err = rbtransport.NewWithOptions(options.UpstreamProxyRequestsNumber, options.UpstreamSock5Proxies...)
		if err != nil {
			return nil, err
		}
	}
	pmux, err := getProxifyServerMux()
	if err != nil {
		return nil, err
	}

	proxy := &Proxy{
		logger:     logger,
		options:    options,
		Dialer:     dialer,
		tinydns:    tdns,
		rbhttp:     rbhttp,
		rbsocks5:   rbsocks5,
		proxifyMux: pmux,
	}

	// Candidate serving core (Step P10): build the single upstream transport
	// once, then the adapter over it. The old Martian core (setupHTTPProxy) and
	// the legacy SOCKS-through-HTTP tunnel (setupLegacySOCKSProxy) are
	// intentionally NOT built by default; they stay compiling for baseline
	// coverage until P17 removes them.
	transport, err := proxy.getRoundTripper()
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to setup transport")
	}
	proxy.transport = transport

	// The adapter needs the CA cert/key files on disk. runner.NewRunner already
	// calls LoadCerts, but a direct library caller of NewProxy may not; call it
	// here (idempotent: loads existing files or generates them) so the adapter
	// never receives cert paths that do not exist yet.
	if err := certs.LoadCerts(options.Directory); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to load CA certificates from %s", options.Directory)
	}

	adapter, err := newMitmproxyAdapter(proxy, transport)
	if err != nil {
		return nil, err
	}
	proxy.adapter = adapter

	return proxy, nil
}

// flowContextKey is the private martian-context key under which the per-flow
// *FlowContext is stored by ModifyRequest and retrieved by ModifyResponse.
const flowContextKey = "proxify-flow-context"

// ModifyRequest is the Martian request-modifier bridge. It stays deliberately
// thin: it establishes the engine-neutral *FlowContext, handles the
// proxy-local short circuit, and delegates all request-side policy to the
// shared modifyRequest. The unified interceptHTTP path (P9+) shares the same
// policy helper. Martian owns the round trip in this phase, so the bridge does
// not call interceptHTTP directly.
func (p *Proxy) ModifyRequest(req *http.Request) error {
	// // Set Content-Length to zero to allow automatic calculation
	req.ContentLength = -1

	ctx := martian.NewContext(req)
	// disable upgrading http connections to https by default
	ctx.Session().MarkInsecure()

	// Build the engine-neutral flow context. Until a protocol adapter supplies
	// distinct identifiers (migration P4+), the martian context ID is used for
	// both the flow and connection id. req.TLS is set by the serving engine for
	// TLS-terminated (MITM'd) flows; the martian fork leaves the session's own
	// secure flag disabled, so req.TLS is the reliable signal here.
	flow := newFlowContext(ctx.ID(), ctx.ID(), req.TLS != nil)
	ctx.Set(flowContextKey, flow)

	// Proxy-local hosts are served synthetically; martian delivers the response
	// by hijacking the client connection (see hijackNServe).
	if p.isProxyLocal(req.Host) {
		return p.hijackNServe(req, ctx)
	}

	return p.modifyRequest(req, flow)
}

func (*Proxy) removeBrEncoding(req *http.Request) {
	encodings := strings.Split(strings.ReplaceAll(req.Header.Get("Accept-Encoding"), " ", ""), ",")
	encodings = sliceutil.PruneEqual(encodings, "br")
	req.Header.Set("Accept-Encoding", strings.Join(encodings, ", "))

}

// ModifyResponse is the Martian response-modifier bridge. Like ModifyRequest
// it is thin: it recovers the *FlowContext established for this flow and
// delegates all response-side policy to the shared modifyResponse.
func (p *Proxy) ModifyResponse(resp *http.Response) error {
	ctx := martian.NewContext(resp.Request)
	// Retrieve the same *FlowContext created for this flow in ModifyRequest.
	var flow *FlowContext
	if w, ok := ctx.Get(flowContextKey); ok {
		flow, _ = w.(*FlowContext)
	}
	return p.modifyResponse(resp, flow)
}

// MatchReplaceRequest strings or regex
func (p *Proxy) MatchReplaceRequest(req *http.Request) error {
	// lazy mode - dump request
	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}

	// lazy mode - ninja level - elaborate
	m := make(map[string]interface{})
	m["request"] = string(reqdump)
	for _, expr := range p.options.RequestMatchReplaceDSL {
		v, err := dsl.EvalExpr(expr, m)
		if err != nil {
			return err
		}
		m["request"] = fmt.Sprint(v)
	}

	reqbuffer := fmt.Sprint(m["request"])
	// lazy mode - epic level - rebuild
	bf := bufio.NewReader(strings.NewReader(reqbuffer))
	requestNew, err := http.ReadRequest(bf)
	if err != nil {
		return err
	}
	// closes old body to allow memory reuse
	_ = req.Body.Close()

	// override original properties
	req.Method = requestNew.Method
	req.Header = requestNew.Header
	req.Body = requestNew.Body
	req.URL = requestNew.URL
	return nil
}

// MatchReplaceRequest strings or regex
func (p *Proxy) MatchReplaceResponse(resp *http.Response) error {
	// // Set Content-Length to zero to allow automatic calculation
	resp.ContentLength = -1

	// lazy mode - dump request
	respdump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}

	// lazy mode - ninja level - elaborate
	m := make(map[string]interface{})
	m["response"] = string(respdump)
	for _, expr := range p.options.ResponseMatchReplaceDSL {
		v, err := dsl.EvalExpr(expr, m)

		if err != nil {
			return err
		}
		m["response"] = fmt.Sprint(v)
	}

	respbuffer := fmt.Sprint(m["response"])
	// lazy mode - epic level - rebuild
	bf := bufio.NewReader(strings.NewReader(respbuffer))
	responseNew, err := http.ReadResponse(bf, nil)
	if err != nil {
		return err
	}

	// closes old body to allow memory reuse
	_ = resp.Body.Close()
	resp.Header = responseNew.Header
	resp.Body, err = readerUtil.NewReusableReadCloser(responseNew.Body)
	if err != nil {
		return err
	}
	if resp.ContentLength == 0 {
		resp.Header.Del("Content-Length")
	}
	// resp.ContentLength = responseNew.ContentLength
	return nil
}

// Run serves the candidate adapter over the configured HTTP and/or SOCKS5
// listeners (migration plan Step P10). Listeners are bound synchronously so a
// bind failure (e.g. an occupied port) returns an error before any serving
// goroutine starts; if one of two configured listeners fails to bind, the
// already-bound one is closed so no half-started server is left running. HTTP is
// served via http.Server.Serve; SOCKS5 connections are accepted in a tracked
// loop and each handed to adapter.ServeSOCKS5. HTTP-only, SOCKS-only, and
// combined configurations are all supported; SOCKS is served directly by the
// adapter and never tunneled through the HTTP proxy.
func (p *Proxy) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	p.runCtx = ctx
	p.runCancel = cancel

	if p.tinydns != nil {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			if err := p.tinydns.Run(); err != nil {
				gologger.Warning().Msgf("Could not start dns server: %s\n", err)
			}
		}()
	}

	// Bind listeners synchronously so bind errors surface from Run. If the SOCKS
	// bind fails after the HTTP listener is up, close the HTTP listener so the
	// caller is not left with a half-started server (and vice versa is moot: the
	// HTTP listener binds first, so no SOCKS listener exists yet if it fails).
	if p.options.ListenAddrHTTP != "" {
		l, err := net.Listen("tcp", p.options.ListenAddrHTTP)
		if err != nil {
			cancel()
			return errorutil.NewWithErr(err).Msgf("failed to bind HTTP listener on %s", p.options.ListenAddrHTTP)
		}
		p.httpListener = l
		// Record the actual bound address before any request is served, so
		// isProxyLocal recognizes proxy-local hosts even with a :0 test port.
		p.listenAddr = l.Addr().String()
	}
	if p.options.ListenAddrSocks5 != "" {
		l, err := net.Listen("tcp", p.options.ListenAddrSocks5)
		if err != nil {
			cancel()
			if p.httpListener != nil {
				_ = p.httpListener.Close()
			}
			return errorutil.NewWithErr(err).Msgf("failed to bind SOCKS5 listener on %s", p.options.ListenAddrSocks5)
		}
		p.socksListener = l
	}

	if p.httpListener != nil {
		p.httpServer = &http.Server{
			Handler:     p.outerHTTPHandler(),
			BaseContext: func(net.Listener) context.Context { return ctx },
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			if err := p.httpServer.Serve(p.httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				gologger.Warning().Msgf("HTTP proxy server stopped: %v", err)
			}
		}()
	}

	if p.socksListener != nil {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.serveSOCKS(ctx, p.socksListener)
		}()
	}

	p.wg.Wait()
	return nil
}

// outerHTTPHandler is the front handler for the HTTP listener. Clear
// proxy-local requests (the banner page and /cacert) are served directly from
// the local mux, bypassing the candidate transport; every CONNECT and
// absolute-form proxy request is handed to the candidate adapter.
func (p *Proxy) outerHTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect && p.isProxyLocal(r.Host) {
			p.proxifyMux.ServeHTTP(w, r)
			return
		}
		p.adapter.ServeHTTP(w, r)
	})
}

// serveSOCKS accepts SOCKS5 connections on l and hands each to the candidate
// adapter in a tracked goroutine. It returns cleanly on context cancellation or
// a closed listener; other accept errors are tolerated with a short backoff so a
// transient failure does not tear down the loop or spin.
func (p *Proxy) serveSOCKS(ctx context.Context, l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			gologger.Warning().Msgf("SOCKS5 accept error: %v", err)
			time.Sleep(5 * time.Millisecond)
			continue
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			if err := p.adapter.ServeSOCKS5(ctx, conn); err != nil {
				gologger.Debug().Msgf("SOCKS5 serve: %v", err)
			}
		}()
	}
}

func (p *Proxy) Stop() {}

// setupLegacySOCKSProxy builds the pre-migration go-socks5 server that tunneled
// SOCKS through the Martian HTTP proxy. Run no longer calls it — the candidate
// adapter serves SOCKS directly and does not tunnel through HTTP — but it is
// retained (with the superproxy/bufiopool tunnel wiring) for compile coverage
// until P17 removes the Martian bridge.
func (p *Proxy) setupLegacySOCKSProxy() error {
	if p.options.ListenAddrSocks5 == "" {
		return nil
	}
	var socks5proxy *socks5.Server
	if p.options.Verbosity <= types.VerbositySilent {
		socks5proxy = socks5.NewServer(
			socks5.WithLogger(socks5.NewLogger(log.New(io.Discard, "", log.Ltime|log.Lshortfile))),
			socks5.WithDial(p.httpTunnelDialer),
		)
	} else {
		socks5proxy = socks5.NewServer(
			socks5.WithDial(p.httpTunnelDialer),
		)
	}
	p.socks5proxy = socks5proxy

	if p.httpProxy != nil {
		httpProxyIP, httpProxyPort, err := net.SplitHostPort(p.options.ListenAddrHTTP)
		if err != nil {
			return err
		}
		httpProxyPortUint, err := strconv.ParseUint(httpProxyPort, 10, 16)
		if err != nil {
			return err
		}
		p.socks5tunnel, err = superproxy.NewSuperProxy(httpProxyIP, uint16(httpProxyPortUint), superproxy.ProxyTypeHTTP, "", "", "")
		if err != nil {
			return err
		}
		p.bufioPool = bufiopool.New(4096, 4096)
	}
	return nil
}

// setupHTTPProxy configures proxy with settings
func (p *Proxy) setupHTTPProxy() error {
	hp := martian.NewProxy()
	hp.Miscellaneous.SetH1ConnectionHeader = true
	hp.Miscellaneous.StripProxyHeaders = true
	hp.Miscellaneous.IgnoreWebSocketError = true
	rt, err := p.getRoundTripper()
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to setup transport")
	}
	hp.SetRoundTripper(rt)
	dialContextFunc := func(ctx context.Context, a, b string) (net.Conn, error) {
		return p.Dialer.Dial(ctx, a, b)
	}
	hp.SetDialContext(dialContextFunc)
	hp.SetMITM(certs.GetMitMConfig())
	p.httpProxy = hp
	return nil
}

func (p *Proxy) httpTunnelDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.socks5tunnel.MakeTunnel(nil, nil, p.bufioPool, addr)
}

// hijackNServe is the Martian-specific delivery shim for proxy-local hosts. It
// hijacks the client connection and writes the response built by the shared
// serveProxyLocal. The candidate path (P9+) returns serveProxyLocal's response
// directly and needs no hijack.
func (p *Proxy) hijackNServe(req *http.Request, ctx *martian.Context) error {
	conn, brw, err := ctx.Session().Hijack()
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()
	resp := p.serveProxyLocal(req)
	if err := resp.Write(brw); err != nil {
		gologger.Warning().Msgf("failed to write response: %v", err)
	}
	if err := brw.Flush(); err != nil {
		gologger.Warning().Msgf("failed to flush buffer: %v", err)
	}
	return nil
}

func getProxifyServerMux() (*http.ServeMux, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %v", err)
	}
	absStaticDirPath := strings.Join([]string{strings.Split(cwd, "cmd")[0], "static"}, "/")

	mux := http.NewServeMux()
	serveStatic := http.FileServer(http.Dir(absStaticDirPath))
	mux.Handle("/", serveStatic)
	// download ca cert
	mux.HandleFunc("/cacert", func(w http.ResponseWriter, r *http.Request) {
		buffer, err := certs.GetRawCA()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			gologger.Warning().Msgf("failed to get raw CA: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\"proxify.pem\"")
		if _, err := w.Write(buffer.Bytes()); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			gologger.Warning().Msgf("failed to write raw CA: %v", err)
			return
		}
	})
	return mux, nil
}
