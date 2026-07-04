package o2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/rclone/rclone/backend/o2/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fshttp"
	"golang.org/x/net/html"
)

const (
	configPhoneNumber   = "phone_number"
	configValidationKey = "validation_key"
	configJSessionID    = "jsessionid"
	configPLC           = "plc"
	configDeviceID      = "device_id"

	statePhone         = "phone"
	stateConfirmReauth = "confirm_reauth"
	stateStartAuth     = "start_auth"
	stateSMSCode       = "sms_code"
)

type authState struct {
	APIURL           string            `json:"api_url"`
	DeviceID         string            `json:"device_id"`
	OldValidationKey string            `json:"old_validation_key"`
	SMSURL           string            `json:"sms_url"`
	Hidden           map[string]string `json:"hidden"`
	Cookies          []authCookieSet   `json:"cookies"`
}

type authCookieSet struct {
	URL     string         `json:"url"`
	Cookies []*http.Cookie `json:"cookies"`
}

type authResult struct {
	ValidationKey string
	JSessionID    string
	PLC           string
	DeviceID      string
}

var browserHeaders = map[string]string{
	"Accept-Language":    "en-US,en;q=0.9",
	"Sec-CH-UA":          `"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`,
	"Sec-CH-UA-Mobile":   "?0",
	"Sec-CH-UA-Platform": `"macOS"`,
	"User-Agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
}

// Config runs the interactive O2 SMS login flow.
func Config(ctx context.Context, name string, m configmap.Mapper, in fs.ConfigIn) (*fs.ConfigOut, error) {
	state, saved := popStateArg(in.State)

	switch state {
	case "":
		opt, err := readOptionsUnchecked(m)
		if err != nil {
			return nil, err
		}
		if opt.PhoneNumber == "" {
			return fs.ConfigInput(statePhone, "config_phone_number", "O2 phone number used to receive the login SMS")
		}
		m.Set(configPhoneNumber, opt.PhoneNumber)
		if opt.ValidationKey != "" && opt.JSessionID != "" && opt.PLC != "" && opt.DeviceID != "" {
			return fs.ConfigConfirm(stateConfirmReauth, false, "config_reauth", "O2 Cloud is already authenticated. Re-authenticate with SMS?")
		}
		return fs.ConfigGoto(stateStartAuth)

	case statePhone:
		phone := normalizePhoneNumber(in.Result)
		if phone == "" {
			return fs.ConfigError("", "O2 phone number can't be blank")
		}
		m.Set(configPhoneNumber, phone)
		return fs.ConfigGoto(stateStartAuth)

	case stateConfirmReauth:
		if in.Result != "true" {
			return nil, nil
		}
		return fs.ConfigGoto(stateStartAuth)

	case stateStartAuth:
		opt, err := readOptionsUnchecked(m)
		if err != nil {
			return nil, err
		}
		if opt.PhoneNumber == "" {
			return fs.ConfigInput(statePhone, "config_phone_number", "O2 phone number used to receive the login SMS")
		}
		if opt.DeviceID == "" {
			opt.DeviceID, err = newDeviceID()
			if err != nil {
				return nil, err
			}
			m.Set(configDeviceID, opt.DeviceID)
		}
		started, err := startSMSAuth(ctx, opt)
		if err != nil {
			return nil, err
		}
		encoded, err := encodeAuthState(started)
		if err != nil {
			return nil, err
		}
		return fs.ConfigInput(fs.StatePush(stateSMSCode, encoded), "config_sms_code", "Enter the O2 SMS verification code")

	case stateSMSCode:
		code := strings.TrimSpace(in.Result)
		if code == "" {
			return fs.ConfigError(in.State, "SMS verification code can't be blank")
		}
		started, err := decodeAuthState(saved)
		if err != nil {
			return nil, err
		}
		result, err := finishSMSAuth(ctx, started, code)
		if err != nil {
			return nil, err
		}
		saveAuthResult(m, result)
		return nil, nil
	}

	return nil, fmt.Errorf("unknown O2 config state %q", in.State)
}

func popStateArg(state string) (string, string) {
	if strings.ContainsRune(state, ',') {
		newState, value := fs.StatePop(state)
		return newState, value
	}
	return state, ""
}

func startSMSAuth(ctx context.Context, opt Options) (authState, error) {
	client := newAuthHTTPClient(ctx)

	startURL, err := mobileConnectURL(opt.APIURL, "start", opt.ValidationKey)
	if err != nil {
		return authState{}, err
	}
	resp, _, err := authRequest(ctx, client, http.MethodPost, startURL, xhrHeaders(opt), formBody(
		"platform", "web",
		"msisdn", opt.PhoneNumber,
		"rememberme", "true",
	))
	if err != nil {
		return authState{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return authState{}, authHTTPError(resp)
	}

	var env api.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return authState{}, err
	}
	if env.Data.AuthorizationURL == "" {
		return authState{}, errors.New("O2 SMS authorization URL missing")
	}

	resp, finalURL, err := authRequest(ctx, client, http.MethodGet, env.Data.AuthorizationURL, navigationHeaders(opt.APIURL, "cross-site"), "")
	if err != nil {
		return authState{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return authState{}, authHTTPError(resp)
	}

	hidden, err := parseHiddenInputs(resp.Body)
	if err != nil {
		return authState{}, err
	}
	if hidden["csrfmiddlewaretoken"] == "" || hidden["corr"] == "" || hidden["nonce"] == "" || hidden["trans"] == "" {
		return authState{}, errors.New("O2 SMS form missing expected hidden fields")
	}

	return authState{
		APIURL:           opt.APIURL,
		DeviceID:         opt.DeviceID,
		OldValidationKey: opt.ValidationKey,
		SMSURL:           finalURL,
		Hidden:           hidden,
		Cookies:          exportAuthCookies(client, opt.APIURL, finalURL),
	}, nil
}

func finishSMSAuth(ctx context.Context, started authState, code string) (authResult, error) {
	client := newAuthHTTPClient(ctx)
	importAuthCookies(client, started.Cookies)

	finishURL := resolveURL(started.SMSURL, "/es/sba/finish")
	resp, finalURL, err := authRequest(ctx, client, http.MethodPost, finishURL, finishHeaders(started), formBody(
		"csrfmiddlewaretoken", started.Hidden["csrfmiddlewaretoken"],
		"corr", started.Hidden["corr"],
		"nonce", started.Hidden["nonce"],
		"trans", started.Hidden["trans"],
		"code", code,
		"action", "finish",
	))
	if err != nil {
		return authResult{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return authResult{}, authHTTPError(resp)
	}

	callback, err := url.Parse(finalURL)
	if err != nil {
		return authResult{}, err
	}
	authorizationCode := callback.Query().Get("code")
	callbackState := callback.Query().Get("state")
	if authorizationCode == "" || callbackState == "" {
		return authResult{}, fmt.Errorf("O2 SMS flow did not return authorization code; final URL was %s", redactedURL(finalURL))
	}

	loginURL, err := mobileConnectURL(started.APIURL, "login", started.OldValidationKey)
	if err != nil {
		return authResult{}, err
	}
	resp, _, err = authRequest(ctx, client, http.MethodPost, loginURL, xhrHeaders(Options{APIURL: started.APIURL, DeviceID: started.DeviceID}), formBody(
		"keytype", "authorizationcode",
		"state", callbackState,
		"key", authorizationCode,
	))
	if err != nil {
		return authResult{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return authResult{}, authHTTPError(resp)
	}

	var env api.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil && err != io.EOF {
		return authResult{}, err
	}

	result := authResult{
		ValidationKey: env.Data.ValidationKey,
		JSessionID:    authCookie(client, started.APIURL, "JSESSIONID"),
		PLC:           authCookie(client, started.APIURL, "PLC"),
		DeviceID:      started.DeviceID,
	}
	if result.ValidationKey == "" {
		result.ValidationKey = authCookie(client, started.APIURL, "validationKey")
	}
	if result.ValidationKey == "" {
		result.ValidationKey, result.JSessionID, result.PLC, err = bootstrapValidationKey(ctx, client, started.APIURL, result)
		if err != nil {
			return authResult{}, err
		}
	}
	if result.ValidationKey == "" || result.JSessionID == "" || result.PLC == "" {
		return authResult{}, errors.New("O2 login did not return a complete session")
	}
	return result, nil
}

func bootstrapValidationKey(ctx context.Context, client *http.Client, apiURL string, result authResult) (string, string, string, error) {
	rawURL := strings.TrimRight(apiURL, "/") + "/sapi/media/folder/root?action=get"
	resp, _, err := authRequest(ctx, client, http.MethodGet, rawURL, apiHeaders(apiURL, result), "")
	if err != nil {
		return "", "", "", err
	}
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var env api.Envelope
		if err := json.NewDecoder(resp.Body).Decode(&env); err == nil && env.Error != nil && env.Error.Data != "" {
			result.ValidationKey = env.Error.Data
			setAuthCookie(client, apiURL, "validationKey", result.ValidationKey)
			result.JSessionID = firstNonEmpty(authCookie(client, apiURL, "JSESSIONID"), result.JSessionID)
			result.PLC = firstNonEmpty(authCookie(client, apiURL, "PLC"), result.PLC)
			rawURL += "&validationkey=" + url.QueryEscape(result.ValidationKey)
			resp, _, err = authRequest(ctx, client, http.MethodGet, rawURL, apiHeaders(apiURL, result), "")
			if err != nil {
				return "", "", "", err
			}
			defer fs.CheckClose(resp.Body, &err)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", "", "", authHTTPError(resp)
	}
	return result.ValidationKey, firstNonEmpty(authCookie(client, apiURL, "JSESSIONID"), result.JSessionID), firstNonEmpty(authCookie(client, apiURL, "PLC"), result.PLC), nil
}

func saveAuthResult(m configmap.Mapper, result authResult) {
	m.Set(configValidationKey, obscure.MustObscure(result.ValidationKey))
	m.Set(configJSessionID, obscure.MustObscure(result.JSessionID))
	m.Set(configPLC, obscure.MustObscure(result.PLC))
	m.Set(configDeviceID, result.DeviceID)
}

func (f *Fs) saveSession() {
	if f.m == nil {
		return
	}
	saveAuthResult(f.m, authResult{
		ValidationKey: f.opt.ValidationKey,
		JSessionID:    f.opt.JSessionID,
		PLC:           f.opt.PLC,
		DeviceID:      f.opt.DeviceID,
	})
}

func newAuthHTTPClient(ctx context.Context) *http.Client {
	jar, _ := cookiejar.New(nil)
	client := fshttp.NewClient(ctx)
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

func authRequest(ctx context.Context, client *http.Client, method, rawURL string, headers map[string]string, body string) (*http.Response, string, error) {
	for i := 0; i < 20; i++ {
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
		if err != nil {
			return nil, "", err
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}
		if resp.StatusCode < 300 || resp.StatusCode > 399 || resp.Header.Get("Location") == "" {
			return resp, rawURL, nil
		}

		statusCode := resp.StatusCode
		nextURL := resolveURL(rawURL, resp.Header.Get("Location"))
		closeResponse(resp)
		rawURL = nextURL
		if statusCode != http.StatusTemporaryRedirect && statusCode != http.StatusPermanentRedirect {
			method = http.MethodGet
			body = ""
		}
	}
	return nil, "", errors.New("too many O2 authentication redirects")
}

func formBody(pairs ...string) string {
	var out strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		if out.Len() > 0 {
			out.WriteByte('&')
		}
		out.WriteString(url.QueryEscape(pairs[i]))
		out.WriteByte('=')
		out.WriteString(url.QueryEscape(pairs[i+1]))
	}
	return out.String()
}

func xhrHeaders(opt Options) map[string]string {
	headers := cloneHeaders(browserHeaders)
	headers["Accept"] = "*/*"
	headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
	headers["Priority"] = "u=1, i"
	headers["Referer"] = strings.TrimRight(opt.APIURL, "/") + "/"
	headers["Sec-Fetch-Dest"] = "empty"
	headers["Sec-Fetch-Mode"] = "cors"
	headers["Sec-Fetch-Site"] = "same-origin"
	headers["X-deviceid"] = opt.DeviceID
	return headers
}

func navigationHeaders(referer, fetchSite string) map[string]string {
	headers := cloneHeaders(browserHeaders)
	headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	headers["Referer"] = strings.TrimRight(referer, "/") + "/"
	headers["Sec-Fetch-Dest"] = "document"
	headers["Sec-Fetch-Mode"] = "navigate"
	headers["Sec-Fetch-Site"] = fetchSite
	headers["Sec-Fetch-User"] = "?1"
	headers["Upgrade-Insecure-Requests"] = "1"
	return headers
}

func finishHeaders(started authState) map[string]string {
	headers := navigationHeaders(started.SMSURL, "same-origin")
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	headers["Origin"] = origin(started.SMSURL)
	headers["Referer"] = started.SMSURL
	if csrf := started.Hidden["csrfmiddlewaretoken"]; csrf != "" {
		headers["X-CSRFToken"] = csrf
	}
	return headers
}

func apiHeaders(apiURL string, result authResult) map[string]string {
	headers := cloneHeaders(browserHeaders)
	headers["Accept"] = "*/*"
	headers["Referer"] = strings.TrimRight(apiURL, "/") + "/"
	headers["X-deviceid"] = result.DeviceID
	cookies := []string{}
	if result.ValidationKey != "" {
		cookies = append(cookies, "validationKey="+result.ValidationKey)
	}
	if result.JSessionID != "" {
		cookies = append(cookies, "JSESSIONID="+result.JSessionID)
	}
	if result.PLC != "" {
		cookies = append(cookies, "PLC="+result.PLC)
	}
	if len(cookies) > 0 {
		headers["Cookie"] = strings.Join(cookies, "; ")
	}
	return headers
}

func cloneHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		out[key] = value
	}
	return out
}

func mobileConnectURL(apiURL, action, validationKey string) (string, error) {
	u, err := url.Parse(strings.TrimRight(apiURL, "/") + "/sapi/login/mobileconnect")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("action", action)
	if validationKey != "" {
		q.Set("validationkey", validationKey)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func parseHiddenInputs(r io.Reader) (map[string]string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}
	hidden := map[string]string{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" && attr(n, "type") == "hidden" {
			if name := attr(n, "name"); name != "" {
				hidden[name] = attr(n, "value")
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return hidden, nil
}

func attr(n *html.Node, name string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, name) {
			return attr.Val
		}
	}
	return ""
}

func encodeAuthState(state authState) (string, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeAuthState(encoded string) (authState, error) {
	var state authState
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return state, err
	}
	return state, json.Unmarshal(data, &state)
}

func exportAuthCookies(client *http.Client, urls ...string) []authCookieSet {
	sets := make([]authCookieSet, 0, len(urls))
	for _, rawURL := range urls {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		sets = append(sets, authCookieSet{URL: origin(u.String()) + "/", Cookies: client.Jar.Cookies(u)})
	}
	return sets
}

func importAuthCookies(client *http.Client, sets []authCookieSet) {
	for _, set := range sets {
		u, err := url.Parse(set.URL)
		if err == nil {
			client.Jar.SetCookies(u, set.Cookies)
		}
	}
}

func authCookie(client *http.Client, rawURL, name string) string {
	u, err := url.Parse(strings.TrimRight(rawURL, "/") + "/")
	if err != nil {
		return ""
	}
	for _, cookie := range client.Jar.Cookies(u) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func setAuthCookie(client *http.Client, rawURL, name, value string) {
	u, err := url.Parse(strings.TrimRight(rawURL, "/") + "/")
	if err == nil {
		client.Jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value}})
	}
}

func authHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if len(body) == 0 {
		return fmt.Errorf("O2 authentication failed: status %d", resp.StatusCode)
	}
	return fmt.Errorf("O2 authentication failed: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func resolveURL(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}

func origin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func normalizePhoneNumber(phone string) string {
	phone = strings.TrimSpace(phone)
	replacer := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "")
	phone = replacer.Replace(phone)
	phone = strings.TrimPrefix(phone, "+")
	if strings.HasPrefix(phone, "00") {
		phone = phone[2:]
	}
	if len(phone) == 9 {
		phone = "34" + phone
	}
	return phone
}

func newDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "web-" + hex.EncodeToString(b[:]), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
