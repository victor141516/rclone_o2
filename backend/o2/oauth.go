package o2

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rclone/rclone/backend/o2/api"
	"github.com/rclone/rclone/fs"
)

const (
	defaultOAuthAuthorizeURL = "https://apiseg.telefonica.es/openid/connect/auth/oauth/v2/o2/cus/authorize"
	defaultOAuthTokenURL     = "https://apiseg.telefonica.es/openid/connect/auth/oauth/v2/o2/cus/token"
	defaultOAuthRedirectURL  = "https://cloud.o2online.es/ui/html/clientoauth.html"
)

var (
	oauthAuthorizeURL = defaultOAuthAuthorizeURL
	oauthTokenURL     = defaultOAuthTokenURL
	oauthRedirectURL  = defaultOAuthRedirectURL
)

// The Android application stores these values encrypted with AES-CBC. Keeping
// the same representation avoids including the OAuth client secret as plain
// text in the source. Like every native-app credential, it must not be treated
// as a security boundary.
var embeddedOAuthClientID = encryptedOAuthValue{
	Ciphertext: "EdJVRQRmvYzoO8ASwglJFwdv+X5kgX2oAjDMu5SzuBKcAFNR8cp6kpU0URf7YJkm",
	Key:        "eAKpUOkIPAE0PLtvGIkniQ==",
	IV:         "JoUuz021igaPNUxS+JnPVw==",
}

var embeddedOAuthClientSecret = encryptedOAuthValue{
	Ciphertext: "QqHFPbxJwRoe+xlK9fc5aGU6r3MdQv3Cj0WjYDhEFPjEog72S4/Zh3fNgy4j/g7E",
	Key:        "ztodpOeuUjjlIPSpZKhzFQ==",
	IV:         "fzh2ZqqMwHtG5edOv9ttCA==",
}

type encryptedOAuthValue struct {
	Ciphertext string
	Key        string
	IV         string
}

type oauthCredentialEnvelope struct {
	Data oauthCredentialData `json:"data"`
}

type oauthCredentialData struct {
	AccessToken     string `json:"accesstoken,omitempty"`
	RefreshToken    string `json:"refreshtoken,omitempty"`
	Platform        string `json:"platform"`
	ExpiresIn       string `json:"expiresin"`
	LastRefreshDate int64  `json:"lastrefreshdate"`
	MSISDN          string `json:"msisdn,omitempty"`
}

type oauthTokenResponse struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	Scope        string          `json:"scope"`
	IDToken      string          `json:"id_token"`
}

type oauthLoginEnvelope struct {
	Data struct {
		ValidationKey string `json:"validationkey"`
		JSessionID    string `json:"jsessionid"`
	} `json:"data"`
	Error *api.Error `json:"error"`
}

func decryptEmbeddedOAuthValue(value encryptedOAuthValue) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(value.Ciphertext)
	if err != nil {
		return "", err
	}
	key, err := base64.StdEncoding.DecodeString(value.Key)
	if err != nil {
		return "", err
	}
	iv, err := base64.StdEncoding.DecodeString(value.IV)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(iv) != block.BlockSize() || len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return "", errors.New("invalid embedded O2 OAuth credential")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	padding := int(plaintext[len(plaintext)-1])
	if padding <= 0 || padding > block.BlockSize() || padding > len(plaintext) {
		return "", errors.New("invalid embedded O2 OAuth credential padding")
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			return "", errors.New("invalid embedded O2 OAuth credential padding")
		}
	}
	return string(plaintext[:len(plaintext)-padding]), nil
}

func oauthClientCredentials() (clientID, clientSecret string, err error) {
	clientID, err = decryptEmbeddedOAuthValue(embeddedOAuthClientID)
	if err != nil {
		return "", "", fmt.Errorf("failed to read O2 OAuth client id: %w", err)
	}
	clientSecret, err = decryptEmbeddedOAuthValue(embeddedOAuthClientSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to read O2 OAuth client secret: %w", err)
	}
	return clientID, clientSecret, nil
}

func (profile providerProfile) oauthClientCredentials() (clientID, clientSecret string, err error) {
	if profile.Name == providerO2 {
		return oauthClientCredentials()
	}
	if profile.OAuthClientID == "" {
		return "", "", fmt.Errorf("%s OAuth client id missing", profile.Description)
	}
	return profile.OAuthClientID, profile.OAuthClientSecret, nil
}

func rawJSONText(value json.RawMessage) string {
	text := strings.TrimSpace(string(value))
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		var decoded string
		if json.Unmarshal(value, &decoded) == nil {
			return decoded
		}
	}
	return text
}

func (f *Fs) oauthAuthorization() (string, error) {
	f.authMu.Lock()
	defer f.authMu.Unlock()
	return oauthAuthorization(f.opt)
}

func (f *Fs) hasOAuthCredentials() bool {
	f.authMu.Lock()
	defer f.authMu.Unlock()
	return f.opt.AccessToken != "" && f.opt.RefreshToken != ""
}

func oauthAuthorization(opt Options) (string, error) {
	profile, err := opt.provider()
	if err != nil {
		return "", err
	}
	return oauthAuthorizationForProfile(opt, profile)
}

func oauthAuthorizationForProfile(opt Options, profile providerProfile) (string, error) {
	if opt.AccessToken == "" || opt.RefreshToken == "" {
		return "", fmt.Errorf("%s OAuth credentials missing", profile.ErrorPrefix)
	}
	payload, err := json.Marshal(oauthCredentialEnvelope{Data: oauthCredentialData{
		AccessToken:     opt.AccessToken,
		RefreshToken:    opt.RefreshToken,
		Platform:        profile.OAuthPlatform,
		ExpiresIn:       firstNonEmpty(opt.OAuthExpiresIn, "0"),
		LastRefreshDate: opt.OAuthLastRefreshDate,
	}})
	if err != nil {
		return "", err
	}
	return "oauth " + base64.StdEncoding.EncodeToString(payload), nil
}

func parseOAuthAuthorization(header string) (oauthCredentialData, bool, error) {
	marker := strings.Index(strings.ToLower(header), "oauth ")
	if marker < 0 {
		return oauthCredentialData{}, false, nil
	}
	encoded := strings.TrimSpace(header[marker+len("oauth "):])
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return oauthCredentialData{}, true, err
	}
	var envelope oauthCredentialEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return oauthCredentialData{}, true, err
	}
	return envelope.Data, true, nil
}

func applyOAuthCredential(opt *Options, credential oauthCredentialData) bool {
	changed := false
	if credential.AccessToken != "" && credential.AccessToken != opt.AccessToken {
		opt.AccessToken = credential.AccessToken
		changed = true
	}
	if credential.RefreshToken != "" && credential.RefreshToken != opt.RefreshToken {
		opt.RefreshToken = credential.RefreshToken
		changed = true
	}
	if credential.ExpiresIn != "" && credential.ExpiresIn != opt.OAuthExpiresIn {
		opt.OAuthExpiresIn = credential.ExpiresIn
		changed = true
	}
	if credential.LastRefreshDate != 0 && credential.LastRefreshDate != opt.OAuthLastRefreshDate {
		opt.OAuthLastRefreshDate = credential.LastRefreshDate
		changed = true
	}
	return changed
}

func (f *Fs) captureOAuthAuthorization(header string) error {
	credential, found, err := parseOAuthAuthorization(header)
	if err != nil {
		return fmt.Errorf("failed to decode rotated O2 OAuth credentials: %w", err)
	}
	if !found {
		return nil
	}
	f.authMu.Lock()
	defer f.authMu.Unlock()
	if applyOAuthCredential(&f.opt, credential) {
		f.saveSessionUnlocked()
	}
	return nil
}

func (f *Fs) oauthNeedsLogin() bool {
	f.authMu.Lock()
	defer f.authMu.Unlock()
	if f.opt.OAuthLastRefreshDate == 0 {
		return true
	}
	expiresIn, err := strconv.ParseInt(f.opt.OAuthExpiresIn, 10, 64)
	if err != nil || expiresIn <= 0 {
		return true
	}
	expiresAt := time.UnixMilli(f.opt.OAuthLastRefreshDate).Add(time.Duration(expiresIn) * time.Second)
	return time.Now().Add(5 * time.Minute).After(expiresAt)
}

func (f *Fs) ensureOAuthSession(ctx context.Context) error {
	if !f.oauthNeedsLogin() {
		return nil
	}
	return f.reloginOAuth(ctx)
}

func (f *Fs) reloginOAuth(ctx context.Context) (err error) {
	f.authMu.Lock()
	defer f.authMu.Unlock()

	profile, err := f.opt.provider()
	if err != nil {
		return err
	}
	authorization, err := oauthAuthorizationForProfile(f.opt, profile)
	if err != nil {
		return err
	}
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.opt.APIURL+"/sapi/login/oauth?action=login", bytes.NewReader(nil))
		if err != nil {
			return false, err
		}
		f.addBaseHeaders(req)
		req.Header.Set("Authorization", authorization)
		req.Header.Set("Accept", "application/json")
		fs.Debugf(f, "Renewing O2 OAuth session")
		resp, err = f.client.Do(req)
		retry, err := shouldRetry(ctx, resp, err)
		if retry {
			closeResponse(resp)
			resp = nil
		}
		return retry, err
	})
	if err != nil {
		closeResponse(resp)
		return err
	}
	defer fs.CheckClose(resp.Body, &err)

	if !successful(resp) {
		return parseAPIError(resp)
	}
	credential, found, err := parseOAuthAuthorization(resp.Header.Get("Authorization"))
	if err != nil {
		return fmt.Errorf("failed to decode O2 OAuth login response: %w", err)
	}
	if found {
		applyOAuthCredential(&f.opt, credential)
	}
	var envelope oauthLoginEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Error != nil {
		return envelopeError(resp.StatusCode, envelope.Error)
	}
	if envelope.Data.ValidationKey == "" || envelope.Data.JSessionID == "" {
		return errors.New("O2 OAuth login did not return a complete session")
	}
	f.opt.ValidationKey = envelope.Data.ValidationKey
	f.opt.JSessionID = envelope.Data.JSessionID
	f.saveSessionUnlocked()
	return nil
}

func exchangeOAuthCode(ctx context.Context, client *http.Client, code, verifier string) (authResult, error) {
	return exchangeOAuthCodeForProfile(ctx, client, Options{}, providerProfile{}, code, verifier)
}

func exchangeOAuthCodeForProfile(ctx context.Context, client *http.Client, opt Options, profile providerProfile, code, verifier string) (authResult, error) {
	if profile.Name == "" {
		var err error
		profile, err = opt.provider()
		if err != nil {
			return authResult{}, err
		}
	}
	clientID, clientSecret, err := profile.oauthClientCredentials()
	if err != nil {
		return authResult{}, err
	}
	formValues := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {profile.OAuthRedirectURL},
		"code_verifier": {verifier},
		"client_id":     {clientID},
	}
	if clientSecret != "" {
		formValues.Set("client_secret", clientSecret)
	}
	form := strings.NewReader(formValues.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, profile.OAuthTokenURL, form)
	if err != nil {
		return authResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addProfileHeaders(req, profile)
	req.Header.Set("User-Agent", profile.APIUserAgent)
	if opt.DeviceID != "" {
		req.Header.Set("X-deviceid", opt.DeviceID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return authResult{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if !successful(resp) {
		return authResult{}, authHTTPError(resp)
	}
	var tokens oauthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return authResult{}, err
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return authResult{}, errors.New("O2 OAuth token response did not return access and refresh tokens")
	}
	return authResult{
		AccessToken:          tokens.AccessToken,
		RefreshToken:         tokens.RefreshToken,
		OAuthExpiresIn:       rawJSONText(tokens.ExpiresIn),
		OAuthLastRefreshDate: 0,
	}, nil
}

func completeOAuthLogin(ctx context.Context, client *http.Client, apiURL, deviceID string, result authResult) (authResult, error) {
	return completeOAuthLoginForProfile(ctx, client, Options{}, providerProfile{}, apiURL, deviceID, result)
}

func completeOAuthLoginForProfile(ctx context.Context, client *http.Client, opt Options, profile providerProfile, apiURL, deviceID string, result authResult) (authResult, error) {
	if profile.Name == "" {
		var err error
		profile, err = opt.provider()
		if err != nil {
			return authResult{}, err
		}
	}
	loginOpt := Options{
		Provider:             profile.Name,
		AccessToken:          result.AccessToken,
		RefreshToken:         result.RefreshToken,
		OAuthExpiresIn:       result.OAuthExpiresIn,
		OAuthLastRefreshDate: result.OAuthLastRefreshDate,
	}
	authorization, err := oauthAuthorizationForProfile(loginOpt, profile)
	if err != nil {
		return authResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiURL, "/")+"/sapi/login/oauth?action=login", bytes.NewReader(nil))
	if err != nil {
		return authResult{}, err
	}
	addProfileHeaders(req, profile)
	req.Header.Set("User-Agent", profile.APIUserAgent)
	req.Header.Set("X-deviceid", deviceID)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return authResult{}, err
	}
	defer fs.CheckClose(resp.Body, &err)
	if !successful(resp) {
		return authResult{}, authHTTPError(resp)
	}
	credential, found, err := parseOAuthAuthorization(resp.Header.Get("Authorization"))
	if err != nil {
		return authResult{}, err
	}
	if found {
		applyOAuthCredential(&loginOpt, credential)
	}
	var envelope oauthLoginEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return authResult{}, err
	}
	if envelope.Error != nil {
		return authResult{}, envelopeError(resp.StatusCode, envelope.Error)
	}
	if envelope.Data.ValidationKey == "" || envelope.Data.JSessionID == "" {
		return authResult{}, errors.New("O2 OAuth login did not return a complete session")
	}
	result.AccessToken = loginOpt.AccessToken
	result.RefreshToken = loginOpt.RefreshToken
	result.OAuthExpiresIn = loginOpt.OAuthExpiresIn
	result.OAuthLastRefreshDate = loginOpt.OAuthLastRefreshDate
	result.ValidationKey = envelope.Data.ValidationKey
	result.JSessionID = envelope.Data.JSessionID
	result.DeviceID = deviceID
	return result, nil
}
