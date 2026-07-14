package proxify

import (
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/pkg/types"
	"github.com/projectdiscovery/proxify/pkg/util"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// flowUserDataKey is the FlowContext key under which the per-flow
// *types.UserData is stored by modifyRequest and retrieved by modifyResponse.
// It replaces the martian-context "user-data" key so the policy functions are
// engine-neutral.
const flowUserDataKey = "user-data"

// delegatedRoundTripper is the transport step of the unified interceptor. It
// performs the network round trip for req and returns the raw response. The
// interceptor supplies it so that request-side policy runs before the round
// trip and response-side policy runs after, without the interceptor itself
// owning transport construction (the caller wires that per mode/route).
type delegatedRoundTripper func(*http.Request) (*http.Response, error)

// interceptHTTP is Proxify's single, protocol-neutral request/response policy
// pipeline. It is usable both by the Martian bridge (via the extracted policy
// helpers it shares) and, from P9 onward, by the mitmproxy-go candidate, which
// calls it directly with a transport as next.
//
// The order is fixed and load-bearing:
//  1. proxy-local short circuit — synthetic hosts are served from the local
//     mux and never reach next (no network round trip);
//  2. request policy/callback — modifyRequest;
//  3. next — the transport round trip;
//  4. repair — guarantee a non-nil body and set resp.Request to the effective
//     request so downstream policy and callers see accurate linkage;
//  5. response policy/callback — modifyResponse;
//  6. return.
//
// ctx is the governing request context; req already carries its own context,
// so ctx is threaded for cancellation-aware callers and future use.
func (p *Proxy) interceptHTTP(ctx context.Context, flow *FlowContext, req *http.Request, next delegatedRoundTripper) (*http.Response, error) {
	_ = ctx

	// 1. proxy-local short circuit: never hits the transport.
	if p.isProxyLocal(req.Host) {
		return p.serveProxyLocal(req), nil
	}

	// 2. request policy/callback.
	if err := p.modifyRequest(req, flow); err != nil {
		return nil, err
	}

	// 3. transport round trip.
	resp, err := next(req)
	if err != nil {
		return nil, err
	}

	// 4. repair: guarantee a usable body and accurate request linkage.
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	resp.Request = req

	// 5. response policy/callback.
	if err := p.modifyResponse(resp, flow); err != nil {
		return nil, err
	}

	// 6. return.
	return resp, nil
}

// isProxyLocal reports whether host addresses Proxify's own local mux (banner
// page, /cacert) rather than an upstream origin. These hosts are served
// synthetically and must never be forwarded.
func (p *Proxy) isProxyLocal(host string) bool {
	return stringsutil.EqualFoldAny(host, "proxify", "proxify:443", "proxify:80", p.listenAddr)
}

// serveProxyLocal serves req against Proxify's local mux and returns the
// resulting response, built via an httptest recorder. The response's Request
// is set to the effective request and Close is set so single-shot serving
// terminates the connection cleanly. It replaces the response-building half of
// the old hijackNServe; the Martian bridge keeps a thin hijack-and-write shim
// around it, and the candidate returns it directly.
func (p *Proxy) serveProxyLocal(req *http.Request) *http.Response {
	rec := httptest.NewRecorder()
	p.proxifyMux.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Close = true
	resp.Request = req
	return resp
}

// modifyRequest applies Proxify's request-side policy to req, recording state
// on flow. When an OnRequestCallback is configured it fully replaces the
// default path (DSL match evaluation, match/replace, br stripping, logging) —
// this is the callback short-circuit. It is protocol-neutral: no serving-engine
// types appear.
func (p *Proxy) modifyRequest(req *http.Request, flow *FlowContext) error {
	userData := types.UserData{
		ID:   flow.ID(),
		Host: req.Host,
	}

	// If callbacks are given use them (for library use cases).
	if p.options.OnRequestCallback != nil {
		return p.options.OnRequestCallback(req, flow)
	}

	boolSlice := []bool{}
	for _, expr := range p.options.RequestDSL {
		m, _ := util.HTTPRequestToMap(req)
		v, err := dsl.EvalExpr(expr, m)
		if err != nil {
			gologger.Warning().Msgf("Could not evaluate request dsl: %s\n", err)
		}
		boolSlice = append(boolSlice, err == nil && v.(bool))
	}
	// evaluate bool array to get match status
	if len(boolSlice) > 0 {
		tmp := util.EvalBoolSlice(boolSlice)
		userData.Match = &tmp
	}

	flow.Set(flowUserDataKey, userData)

	// perform match and replace
	if len(p.options.RequestMatchReplaceDSL) != 0 {
		_ = p.MatchReplaceRequest(req)
	}
	p.removeBrEncoding(req)
	_ = p.logger.LogRequest(req, userData)
	return nil
}

// modifyResponse applies Proxify's response-side policy to resp using the flow
// created for the request. When an OnResponseCallback is configured it fully
// replaces the default path (DSL match evaluation, match/replace, logging,
// redirect handling) — the callback short-circuit. It is protocol-neutral.
func (p *Proxy) modifyResponse(resp *http.Response, flow *FlowContext) error {
	var userData *types.UserData
	if flow != nil {
		if w, ok := flow.Get(flowUserDataKey); ok {
			if data, ok2 := w.(types.UserData); ok2 {
				userData = &data
			}
		}
	}
	if userData == nil {
		gologger.Warning().Msgf("something went wrong got response without userData")
		// pass empty struct to avoid panic
		userData = &types.UserData{}
	}
	userData.HasResponse = true

	// if content-length is zero remove header
	if resp.ContentLength == 0 {
		resp.Header.Del("Content-Length")
	}

	// If callbacks are given use them (for library use cases).
	if p.options.OnResponseCallback != nil {
		if flow == nil {
			// No request-side flow context (e.g. response without a tracked
			// request); provide a fresh one so callbacks never receive nil.
			flow = newFlowContext("", "", resp.TLS != nil)
		}
		return p.options.OnResponseCallback(resp, flow)
	}

	boolSlice := []bool{}
	for _, expr := range p.options.ResponseDSL {
		m, _ := util.HTTPResponseToMap(resp)
		v, err := dsl.EvalExpr(expr, m)
		if err != nil {
			gologger.Warning().Msgf("Could not evaluate response dsl: %s\n", err)
		}
		boolSlice = append(boolSlice, err == nil && v.(bool))
	}
	if len(boolSlice) > 0 {
		tmp := util.EvalBoolSlice(boolSlice)
		// finalize
		if userData.Match != nil {
			tmp = *userData.Match && tmp
		}
		userData.Match = &tmp
	}
	// perform match and replace
	if len(p.options.ResponseMatchReplaceDSL) != 0 {
		_ = p.MatchReplaceResponse(resp)
	}
	_ = p.logger.LogResponse(resp, *userData)
	if resp.StatusCode == 301 || resp.StatusCode == 302 {
		// set connection close header
		// close connection if redirected to different host
		if loc, err := resp.Location(); err == nil {
			if loc.Host == resp.Request.Host {
				// if same host redirect do not close connection
				return nil
			}
		}
		resp.Close = true
	}
	return nil
}
