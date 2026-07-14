package proxify

import (
	"bufio"
	"context"
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
	"github.com/projectdiscovery/proxify/pkg/util"
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

	if err := proxy.setupHTTPProxy(); err != nil {
		return nil, err
	}

	var socks5proxy *socks5.Server
	if options.ListenAddrSocks5 != "" {
		if options.Verbosity <= types.VerbositySilent {
			socks5proxy = socks5.NewServer(
				socks5.WithLogger(socks5.NewLogger(log.New(io.Discard, "", log.Ltime|log.Lshortfile))),
				socks5.WithDial(proxy.httpTunnelDialer),
			)
		} else {
			socks5proxy = socks5.NewServer(
				socks5.WithDial(proxy.httpTunnelDialer),
			)
		}
	}

	proxy.socks5proxy = socks5proxy

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

func (p *Proxy) Run() error {
	var wg sync.WaitGroup

	if p.tinydns != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.tinydns.Run(); err != nil {
				gologger.Warning().Msgf("Could not start dns server: %s\n", err)
			}
		}()
	}

	// http proxy
	if p.httpProxy != nil {
		p.httpProxy.TLSPassthroughFunc = func(req *http.Request) bool {
			// Skip MITM for hosts that are in pass-through list
			return util.MatchAnyRegex(p.options.PassThrough, req.Host)
		}

		p.httpProxy.SetRequestModifier(p)
		p.httpProxy.SetResponseModifier(p)

		l, err := net.Listen("tcp", p.options.ListenAddrHTTP)
		if err != nil {
			gologger.Fatal().Msgf("failed to setup listener got %v", err)
		}
		p.listenAddr = l.Addr().String()
		wg.Add(1)
		go func() {
			defer wg.Done()
			gologger.Fatal().Msgf("%v", p.httpProxy.Serve(l))
		}()
	}

	// socks5 proxy
	if p.socks5proxy != nil {
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

		wg.Add(1)
		go func() {
			defer wg.Done()

			gologger.Fatal().Msgf("%v", p.socks5proxy.ListenAndServe("tcp", p.options.ListenAddrSocks5))
		}()
	}

	wg.Wait()
	return nil
}

func (p *Proxy) Stop() {}

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
