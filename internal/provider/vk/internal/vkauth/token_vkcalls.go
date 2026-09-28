package vkauth

// Captcha-free anonymous-join flow through VK Calls' own mobile API. VK gates
// anonymous flows per (host, method, client_id): the legacy web path
// (api.vk.ru/method/calls.getAnonymousToken, see token_call.go) is
// captcha-gated and, since VK tightened detection on 2026-05-15, its PoW
// solver no longer passes. This path is the one the native VK Calls app uses -
// api.vk.me with VK Connect's public client_id 8093730 (no secret) - and VK
// treats those anonymous tokens as already-trusted identity, so it is not
// captcha-gated. If VK ever gates it too, fetch() falls back to the legacy
// path with its PoW/manual captcha solver.
//
// The flow was discovered and documented by anton48/vk-turn-proxy-ios; the
// three api.vk.me steps below mirror it. Steps 4-5 (calls.okcdn.ru) are shared
// with the legacy path (token_oksession.go, token_creds.go).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	neturl "net/url"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/namegen"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"

	"github.com/google/uuid"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/personanet"
)

const (
	vkCallsAPIHost    = "api.vk.me"
	vkConnectClientID = "8093730"
	vkCallsAPIVersion = "5.276"
	// iosUA identifies the native VK Calls app. Paired with the Safari iOS TLS
	// profile (personanet.NewSafariIOSClient); a Chrome UA/JA3 here is rejected.
	// This path is not a WebView, so it sends no Origin/Referer.
	iosUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
)

// getTokenChainVKCalls runs the captcha-free VK Calls flow for one link and
// returns TURN credentials. Any VK API error (including a captcha gate) is
// returned so fetch() can fall back to the legacy credential loop.
func (c *Client) getTokenChainVKCalls(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	httpClient := c.vkCallsClient
	if httpClient == nil {
		cl, err := personanet.NewSafariIOSClient(c.dialer, personanet.NewCookieJar())
		if err != nil {
			return "", "", nil, fmt.Errorf("vkcalls: init ios client: %w", err)
		}
		httpClient = cl
	}
	profile := c.currentPersona()

	device := uuid.New().String()
	linkURL := neturl.QueryEscape("https://vk.ru/call/join/" + link)
	name := namegen.Generate()
	nameEsc := neturl.QueryEscape(name)

	c.log.Debugf("[STREAM %d] [VK Auth] captcha-free path via %s (client_id=%s)", streamID, vkCallsAPIHost, vkConnectClientID)

	// 1. anonymous token from VK Connect.
	r, err := c.vkCallsGet(ctx, httpClient, fmt.Sprintf(
		"https://%s/method/auth.getAnonymToken?v=%s&client_id=%s&link=%s&device_id=%s&anonymName=%s&lang=en",
		vkCallsAPIHost, vkCallsAPIVersion, vkConnectClientID, linkURL, device, nameEsc))
	if err != nil {
		return "", "", nil, err
	}
	if e := vkCallsErr(r); e != nil {
		return "", "", nil, fmt.Errorf("vkcalls auth.getAnonymToken: %w", e)
	}
	anon := vkCallsRespToken(r)
	if anon == "" {
		return "", "", nil, fmt.Errorf("vkcalls auth.getAnonymToken: missing response.token")
	}
	anonEsc := neturl.QueryEscape(anon)
	if delayErr := vkDelayRandom(ctx, 100, 150); delayErr != nil {
		return "", "", nil, delayErr
	}

	// 2. call preview confirms the call exists; when VK returns user_id/secret
	//    they must be replayed on the next step.
	r, err = c.vkCallsGet(ctx, httpClient, fmt.Sprintf(
		"https://%s/method/messages.getCallPreview?v=%s&anonymous_token=%s&device_id=%s&extended=1&fields=first_name&lang=en&link=%s",
		vkCallsAPIHost, vkCallsAPIVersion, anonEsc, device, linkURL))
	if err != nil {
		return "", "", nil, err
	}
	if e := vkCallsErr(r); e != nil {
		return "", "", nil, fmt.Errorf("vkcalls messages.getCallPreview: %w", e)
	}
	extra := ""
	if resp, ok := r["response"].(map[string]any); ok {
		if uid, ok := resp["user_id"].(float64); ok {
			extra += fmt.Sprintf("&user_id=%.0f", uid)
		}
		if secret, _ := resp["secret"].(string); secret != "" {
			extra += "&secret=" + neturl.QueryEscape(secret)
		}
	}
	if delayErr := vkDelayRandom(ctx, 100, 150); delayErr != nil {
		return "", "", nil, delayErr
	}

	// 3. anonymous call token - the gate that captcha'd the legacy path.
	r, err = c.vkCallsGet(ctx, httpClient, fmt.Sprintf(
		"https://%s/method/messages.getAnonymCallToken?v=%s&anonymous_token=%s&device_id=%s&link=%s&name=%s%s&lang=en",
		vkCallsAPIHost, vkCallsAPIVersion, anonEsc, device, linkURL, nameEsc, extra))
	if err != nil {
		return "", "", nil, err
	}
	if e := vkCallsErr(r); e != nil {
		return "", "", nil, fmt.Errorf("vkcalls messages.getAnonymCallToken: %w", e)
	}
	callToken := vkCallsRespToken(r)
	if callToken == "" {
		return "", "", nil, fmt.Errorf("vkcalls messages.getAnonymCallToken: missing response.token")
	}
	if delayErr := vkDelayRandom(ctx, 100, 150); delayErr != nil {
		return "", "", nil, delayErr
	}

	// 4-5. OK anonymLogin -> session_key, then join -> TURN creds. Same
	// calls.okcdn.ru steps the legacy path uses; okcdn is not fingerprint-gated.
	sessionKey, err := c.fetchOkRuSession(ctx, httpClient, profile)
	if err != nil {
		return "", "", nil, fmt.Errorf("vkcalls okru session: %w", err)
	}
	if delayErr := vkDelayRandom(ctx, 100, 150); delayErr != nil {
		return "", "", nil, delayErr
	}
	return c.fetchTurnCreds(ctx, httpClient, profile, streamID, link, callToken, sessionKey)
}

// vkCallsGet issues one bodiless POST (VK Calls puts every parameter in the
// URL) with the native-app header set and returns the parsed JSON. VK often
// resets a pooled HTTP/2 connection; on a transport error it drops idle
// connections and retries once on a fresh one.
func (c *Client) vkCallsGet(ctx context.Context, httpClient tlsclient.HttpClient, url string) (map[string]any, error) {
	do := func() (*fhttp.Response, error) {
		req, err := fhttp.NewRequestWithContext(ctx, fhttp.MethodPost, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", iosUA)
		req.Header.Set("Accept", "*/*")
		return httpClient.Do(req)
	}

	resp, err := do()
	if err != nil {
		httpClient.CloseIdleConnections()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		resp, err = do()
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.log.Warnf("[VK Auth] close vkcalls response body: %s", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("vkcalls decode response: %w", err)
	}
	return m, nil
}

// vkCallsRespToken pulls response.token out of a VK Calls reply.
func vkCallsRespToken(r map[string]any) string {
	resp, ok := r["response"].(map[string]any)
	if !ok {
		return ""
	}
	token, _ := resp["token"].(string)
	return token
}

// vkCallsErr turns a VK {"error": {...}} envelope into an error. The
// "error_code:<n>" shape matches the rate-limit heuristic in fetch().
func vkCallsErr(r map[string]any) error {
	e, ok := r["error"].(map[string]any)
	if !ok {
		return nil
	}
	code := 0
	if f, ok := e["error_code"].(float64); ok {
		code = int(f)
	}
	msg, _ := e["error_msg"].(string)
	return fmt.Errorf("error_code:%d %s", code, msg)
}
