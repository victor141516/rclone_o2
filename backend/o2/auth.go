package o2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fshttp"
)

const (
	configPhoneNumber          = "phone_number"
	configValidationKey        = "validation_key"
	configJSessionID           = "jsessionid"
	configDeviceID             = "device_id"
	configAccessToken          = "access_token"
	configRefreshToken         = "refresh_token"
	configOAuthExpiresIn       = "oauth_expires_in"
	configOAuthLastRefreshDate = "oauth_last_refresh_date"

	statePhone         = "phone"
	stateConfirmReauth = "confirm_reauth"
	stateStartAuth     = "start_auth"
	stateSMSCode       = "sms_code"
)

type authState struct {
	Provider     string          `json:"provider"`
	APIURL       string          `json:"api_url"`
	DeviceID     string          `json:"device_id"`
	LoginURL     string          `json:"login_url"`
	RedirectURL  string          `json:"redirect_url"`
	OTPAPIURL    string          `json:"otp_api_url"`
	Mobile       string          `json:"mobile"`
	OAuthState   string          `json:"oauth_state"`
	CodeVerifier string          `json:"code_verifier"`
	SessionID    string          `json:"session_id"`
	SessionData  string          `json:"session_data"`
	Cookies      []authCookieSet `json:"cookies"`
}

type t3Environment struct {
	APIGatewayURL string `json:"apiGwUrl"`
}

type t3ManageCredentialResponse struct {
	NewSessionID   string         `json:"newSessionID"`
	NewSessionData string         `json:"newSessionData"`
	FaultDetail    *t3FaultDetail `json:"faultDetail"`
}

type t3VerifyCredentialResponse struct {
	RedirectURI string         `json:"redirectUri"`
	FaultDetail *t3FaultDetail `json:"faultDetail"`
}

type t3FaultDetail struct {
	ErrorID          string `json:"errorId"`
	ErrorDescription string `json:"errorDescription"`
}

type authCookieSet struct {
	URL     string         `json:"url"`
	Cookies []*http.Cookie `json:"cookies"`
}

type authResult struct {
	ValidationKey        string
	JSessionID           string
	DeviceID             string
	AccessToken          string
	RefreshToken         string
	OAuthExpiresIn       string
	OAuthLastRefreshDate int64
}

var browserHeaders = map[string]string{
	"Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
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
		profile, err := opt.provider()
		if err != nil {
			return nil, err
		}
		if opt.PhoneNumber == "" {
			return fs.ConfigInput(statePhone, "config_phone_number", profile.Description+" phone number used to receive the login SMS")
		}
		m.Set(configPhoneNumber, opt.PhoneNumber)
		if opt.AccessToken != "" && opt.RefreshToken != "" && opt.DeviceID != "" {
			return fs.ConfigConfirm(stateConfirmReauth, false, "config_reauth", profile.Description+" is already authenticated. Re-authenticate with SMS?")
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
			profile, err := opt.provider()
			if err != nil {
				return nil, err
			}
			return fs.ConfigInput(statePhone, "config_phone_number", profile.Description+" phone number used to receive the login SMS")
		}
		if opt.DeviceID == "" {
			profile, err := opt.provider()
			if err != nil {
				return nil, err
			}
			opt.DeviceID, err = newDeviceID(profile)
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
		return fs.ConfigInput(fs.StatePush(stateSMSCode, encoded), "config_sms_code", "Enter the "+started.providerDescription()+" SMS verification code")

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

func (state authState) providerDescription() string {
	profile, err := (Options{Provider: state.Provider}).provider()
	if err != nil {
		return "O2 Cloud"
	}
	return profile.Description
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

	profile, err := opt.provider()
	if err != nil {
		return authState{}, err
	}
	clientID, _, err := profile.oauthClientCredentials()
	if err != nil {
		return authState{}, err
	}
	codeVerifier, err := newRandomBase64URL(48)
	if err != nil {
		return authState{}, err
	}
	codeChallengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeHash[:])
	oauthState, err := newRandomBase64URL(32)
	if err != nil {
		return authState{}, err
	}
	nonce, err := newRandomHex()
	if err != nil {
		return authState{}, err
	}
	authorizeURL, err := url.Parse(profile.OAuthAuthorizeURL)
	if err != nil {
		return authState{}, err
	}
	authorizeQuery := authorizeURL.Query()
	authorizeQuery.Set("response_type", "code")
	authorizeQuery.Set("client_id", clientID)
	authorizeQuery.Set("redirect_uri", profile.OAuthRedirectURL)
	authorizeQuery.Set("access_type", profile.OAuthAccessType)
	authorizeQuery.Set("scope", profile.OAuthScope)
	authorizeQuery.Set("state", oauthState)
	authorizeQuery.Set("nonce", nonce)
	authorizeQuery.Set("code_challenge", codeChallenge)
	authorizeQuery.Set("code_challenge_method", "S256")
	authorizeQuery.Set("acr_values", "2")
	if profile.Name == providerMovistar {
		authorizeQuery.Set("lang", "en")
	}
	authorizeURL.RawQuery = authorizeQuery.Encode()

	resp, loginURL, err := authRequest(ctx, client, http.MethodGet, authorizeURL.String(), navigationHeaders(profile, opt.APIURL, "cross-site"), "")
	if err != nil {
		return authState{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return authState{}, authHTTPError(resp)
	}

	loginParameters, err := authFragmentParameters(loginURL)
	if err != nil {
		return authState{}, err
	}
	sessionID := loginParameters.Get("sessionID")
	sessionData := loginParameters.Get("sessionData")
	consumerID := loginParameters.Get(profile.ConsumerParam)
	if sessionID == "" || sessionData == "" || consumerID == "" || loginParameters.Get("state") == "" {
		return authState{}, fmt.Errorf("%s login did not return the required session parameters", profile.ErrorPrefix)
	}
	if loginParameters.Get("state") != oauthState {
		return authState{}, fmt.Errorf("%s login returned an invalid OAuth state", profile.ErrorPrefix)
	}
	loginPageURL := stripURLFragment(loginURL)
	redirectURL := profile.OAuthRedirectURL

	environmentURL := resolveURL(loginPageURL, "/coco-envInfo/env.json")
	resp, _, err = authRequest(ctx, client, http.MethodGet, environmentURL, jsonHeaders(profile, loginPageURL), "")
	if err != nil {
		return authState{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return authState{}, authHTTPError(resp)
	}
	var environment t3Environment
	if err := json.NewDecoder(resp.Body).Decode(&environment); err != nil {
		return authState{}, err
	}
	if environment.APIGatewayURL == "" {
		return authState{}, fmt.Errorf("%s authentication API gateway URL missing", profile.ErrorPrefix)
	}

	mobile := localMobileNumber(opt.PhoneNumber)
	managePayload := map[string]string{
		profile.ManageMobileKey:  mobile,
		profile.ManageSessionKey: sessionID,
		"sessionData":            sessionData,
		"consumerId":             consumerID,
	}
	requestBody, err := json.Marshal(managePayload)
	if err != nil {
		return authState{}, err
	}
	manageURL := strings.TrimRight(environment.APIGatewayURL, "/") + profile.ManagePath
	resp, _, err = authRequest(ctx, client, http.MethodPost, manageURL, t3Headers(profile, loginPageURL), string(requestBody))
	if err != nil {
		return authState{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return authState{}, smsAuthHTTPError(resp)
	}
	var managed t3ManageCredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&managed); err != nil {
		return authState{}, err
	}
	if managed.FaultDetail != nil {
		return authState{}, smsFaultError(managed.FaultDetail)
	}
	sessionID = firstNonEmpty(managed.NewSessionID, sessionID)
	sessionData = firstNonEmpty(managed.NewSessionData, sessionData)

	return authState{
		Provider:     profile.Name,
		APIURL:       opt.APIURL,
		DeviceID:     opt.DeviceID,
		LoginURL:     loginPageURL,
		RedirectURL:  redirectURL,
		OTPAPIURL:    environment.APIGatewayURL,
		Mobile:       mobile,
		OAuthState:   oauthState,
		CodeVerifier: codeVerifier,
		SessionID:    sessionID,
		SessionData:  sessionData,
		Cookies:      exportAuthCookies(client, opt.APIURL, authorizeURL.String(), loginPageURL, environment.APIGatewayURL),
	}, nil
}

func finishSMSAuth(ctx context.Context, started authState, code string) (authResult, error) {
	client := newAuthHTTPClient(ctx)
	importAuthCookies(client, started.Cookies)
	profile, err := (Options{Provider: started.Provider}).provider()
	if err != nil {
		return authResult{}, err
	}

	requestBody, err := json.Marshal(map[string]string{
		"otp":                    code,
		"sessionData":            started.SessionData,
		profile.VerifySessionKey: started.SessionID,
		"Mobile":                 started.Mobile,
	})
	if err != nil {
		return authResult{}, err
	}
	verifyURL := strings.TrimRight(started.OTPAPIURL, "/") + profile.VerifyPath
	resp, _, err := authRequest(ctx, client, http.MethodPost, verifyURL, t3Headers(profile, started.LoginURL), string(requestBody))
	if err != nil {
		return authResult{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return authResult{}, smsAuthHTTPError(resp)
	}

	var verified t3VerifyCredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&verified); err != nil {
		return authResult{}, err
	}
	if verified.FaultDetail != nil {
		return authResult{}, smsFaultError(verified.FaultDetail)
	}
	if verified.RedirectURI == "" {
		return authResult{}, fmt.Errorf("%s SMS verification did not return a redirect URL", profile.ErrorPrefix)
	}
	callbackURL, err := url.Parse(verified.RedirectURI)
	if err != nil {
		return authResult{}, err
	}
	redirectURL, err := url.Parse(started.RedirectURL)
	if err != nil {
		return authResult{}, err
	}
	if callbackURL.Scheme != redirectURL.Scheme || callbackURL.Host != redirectURL.Host || callbackURL.Path != redirectURL.Path {
		return authResult{}, fmt.Errorf("%s SMS login returned an unexpected callback URL: %s", profile.ErrorPrefix, redactedURL(verified.RedirectURI))
	}
	callbackQuery := callbackURL.Query()
	if callbackQuery.Get("state") == "" || callbackQuery.Get("state") != started.OAuthState {
		return authResult{}, fmt.Errorf("%s SMS login returned an invalid OAuth state", profile.ErrorPrefix)
	}
	authorizationCode := callbackQuery.Get("code")
	if authorizationCode == "" {
		return authResult{}, fmt.Errorf("%s SMS login did not return an authorization code", profile.ErrorPrefix)
	}

	result, err := exchangeOAuthCodeForProfile(ctx, client, Options{Provider: profile.Name, DeviceID: started.DeviceID}, profile, authorizationCode, started.CodeVerifier)
	if err != nil {
		return authResult{}, err
	}
	return completeOAuthLoginForProfile(ctx, client, Options{Provider: profile.Name}, profile, started.APIURL, started.DeviceID, result)
}

func saveAuthResult(m configmap.Mapper, result authResult) {
	m.Set(configValidationKey, obscure.MustObscure(result.ValidationKey))
	m.Set(configJSessionID, obscure.MustObscure(result.JSessionID))
	m.Set(configDeviceID, result.DeviceID)
	m.Set(configAccessToken, obscure.MustObscure(result.AccessToken))
	m.Set(configRefreshToken, obscure.MustObscure(result.RefreshToken))
	m.Set(configOAuthExpiresIn, result.OAuthExpiresIn)
	m.Set(configOAuthLastRefreshDate, fmt.Sprint(result.OAuthLastRefreshDate))
}

func (f *Fs) saveSessionUnlocked() {
	if f.m == nil {
		return
	}
	saveAuthResult(f.m, authResult{
		ValidationKey:        f.opt.ValidationKey,
		JSessionID:           f.opt.JSessionID,
		DeviceID:             f.opt.DeviceID,
		AccessToken:          f.opt.AccessToken,
		RefreshToken:         f.opt.RefreshToken,
		OAuthExpiresIn:       f.opt.OAuthExpiresIn,
		OAuthLastRefreshDate: f.opt.OAuthLastRefreshDate,
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

		fs.Debugf(nil, "O2 auth request method=%s url=%s", method, redactedURL(rawURL))
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}
		fs.Debugf(nil, "O2 auth response status=%d url=%s", resp.StatusCode, redactedURL(rawURL))
		if cookies := resp.Cookies(); len(cookies) > 0 {
			cookieNames := make([]string, 0, len(cookies))
			for _, cookie := range cookies {
				cookieNames = append(cookieNames, cookie.Name)
			}
			fs.Debugf(nil, "O2 auth response set_cookies=%q url=%s", cookieNames, redactedURL(rawURL))
		}
		if resp.StatusCode < 300 || resp.StatusCode > 399 || resp.Header.Get("Location") == "" {
			return resp, rawURL, nil
		}

		statusCode := resp.StatusCode
		nextURL := resolveURL(rawURL, resp.Header.Get("Location"))
		fs.Debugf(nil, "O2 auth redirect status=%d from=%s to=%s", statusCode, redactedURL(rawURL), redactedURL(nextURL))
		closeResponse(resp)
		rawURL = nextURL
		if statusCode != http.StatusTemporaryRedirect && statusCode != http.StatusPermanentRedirect {
			method = http.MethodGet
			body = ""
		}
	}
	return nil, "", errors.New("too many O2 authentication redirects")
}

func navigationHeaders(profile providerProfile, referer, fetchSite string) map[string]string {
	headers := profileBrowserHeaders(profile)
	headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	headers["Referer"] = strings.TrimRight(stripURLFragment(referer), "/") + "/"
	headers["Sec-Fetch-Dest"] = "document"
	headers["Sec-Fetch-Mode"] = "navigate"
	headers["Sec-Fetch-Site"] = fetchSite
	headers["Sec-Fetch-User"] = "?1"
	headers["Upgrade-Insecure-Requests"] = "1"
	return headers
}

func jsonHeaders(profile providerProfile, referer string) map[string]string {
	headers := profileBrowserHeaders(profile)
	headers["Accept"] = "application/json, text/plain, */*"
	headers["Referer"] = stripURLFragment(referer)
	headers["Sec-Fetch-Dest"] = "empty"
	headers["Sec-Fetch-Mode"] = "cors"
	headers["Sec-Fetch-Site"] = "same-origin"
	return headers
}

func t3Headers(profile providerProfile, referer string) map[string]string {
	headers := jsonHeaders(profile, referer)
	headers["Content-Type"] = "application/json"
	headers["Origin"] = origin(referer)
	headers["Sec-Fetch-Site"] = "cross-site"
	return headers
}

func cloneHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		out[key] = value
	}
	return out
}

func profileBrowserHeaders(profile providerProfile) map[string]string {
	headers := cloneHeaders(browserHeaders)
	if profile.BrowserUserAgent != "" {
		headers["User-Agent"] = profile.BrowserUserAgent
	}
	if profile.XRequestedWith != "" {
		headers["X-Requested-With"] = profile.XRequestedWith
	}
	return headers
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

func authHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if len(body) == 0 {
		return fmt.Errorf("O2 authentication failed: status %d", resp.StatusCode)
	}
	return fmt.Errorf("O2 authentication failed: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func smsAuthHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var envelope struct {
		FaultDetail *t3FaultDetail `json:"faultDetail"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.FaultDetail != nil {
		return smsFaultError(envelope.FaultDetail)
	}
	return fmt.Errorf("O2 SMS authorization failed: status %d", resp.StatusCode)
}

func smsFaultError(fault *t3FaultDetail) error {
	switch {
	case fault == nil:
		return errors.New("O2 SMS authorization failed")
	case fault.ErrorID != "" && fault.ErrorDescription != "":
		return fmt.Errorf("O2 SMS authorization failed: %s: %s", fault.ErrorID, fault.ErrorDescription)
	case fault.ErrorID != "":
		return fmt.Errorf("O2 SMS authorization failed: %s", fault.ErrorID)
	case fault.ErrorDescription != "":
		return fmt.Errorf("O2 SMS authorization failed: %s", fault.ErrorDescription)
	default:
		return errors.New("O2 SMS authorization failed")
	}
}

func authFragmentParameters(rawURL string) (url.Values, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	_, query, found := strings.Cut(u.Fragment, "?")
	if !found {
		return nil, errors.New("O2 login URL is missing its session parameters")
	}
	return url.ParseQuery(query)
}

func stripURLFragment(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
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

func localMobileNumber(phone string) string {
	phone = normalizePhoneNumber(phone)
	if len(phone) == 11 && strings.HasPrefix(phone, "34") {
		return phone[2:]
	}
	return phone
}

func newRandomHex() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func newDeviceID(profile providerProfile) (string, error) {
	if profile.DevicePrefix == "mox-" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		value := base64.StdEncoding.EncodeToString(b)
		return profile.DevicePrefix + value, nil
	}
	id, err := newRandomHex()
	if err != nil {
		return "", err
	}
	return firstNonEmpty(profile.DevicePrefix, "fac-") + id, nil
}

func newRandomBase64URL(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
