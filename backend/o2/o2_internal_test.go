package o2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rclone/rclone/backend/o2/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/vfs"
	"github.com/rclone/rclone/vfs/vfscommon"
)

func TestRevealO2Secrets(t *testing.T) {
	validationKey := "24553931775f412a57804d272b305848"
	jsessionid := "2D4F6F492842ADB18DEB929ACE9984E8.1i221"

	if got := revealValidationKey(validationKey); got != validationKey {
		t.Fatalf("raw validation key changed to %q", got)
	}
	if got := revealJSessionID(jsessionid); got != jsessionid {
		t.Fatalf("raw JSESSIONID changed to %q", got)
	}
	if got := revealValidationKey(obscure.MustObscure(validationKey)); got != validationKey {
		t.Fatalf("obscured validation key revealed as %q", got)
	}
	if got := revealJSessionID(obscure.MustObscure(jsessionid)); got != jsessionid {
		t.Fatalf("obscured JSESSIONID revealed as %q", got)
	}
}

func TestNormalizeDeviceID(t *testing.T) {
	for _, test := range []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "web-test-device", want: "web-test-device"},
		{in: "fac-test-device", want: "fac-test-device"},
		{in: "test-device", want: "web-test-device"},
		{in: " test-device ", want: "web-test-device"},
	} {
		if got := normalizeDeviceID(test.in); got != test.want {
			t.Fatalf("normalizeDeviceID(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestNormalizePhoneNumber(t *testing.T) {
	for _, test := range []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "600111222", want: "34600111222"},
		{in: "+34 600 111 222", want: "34600111222"},
		{in: "0034-600-111-222", want: "34600111222"},
	} {
		if got := normalizePhoneNumber(test.in); got != test.want {
			t.Fatalf("normalizePhoneNumber(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestOptionsValidateRequiresAndroidOAuth(t *testing.T) {
	opt := Options{
		PhoneNumber:  "34600000000",
		DeviceID:     "fac-device-id",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}
	if err := opt.validate(); err == nil {
		t.Fatal("Android OAuth credentials without login session were accepted")
	}
	opt.ValidationKey = "validation-key"
	opt.JSessionID = "session-id"
	if err := opt.validate(); err != nil {
		t.Fatalf("Android OAuth session rejected: %v", err)
	}
	opt.RefreshToken = ""
	if err := opt.validate(); err == nil {
		t.Fatal("legacy web-only session was accepted")
	}
}

func decodeUploadMetadata(t *testing.T, name string, modTime time.Time) map[string]any {
	t.Helper()
	got, err := uploadMetadata(name, 42, 123, modTime)
	if err != nil {
		t.Fatal(err)
	}

	var payload map[string]map[string]any
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatal(err)
	}
	return payload["data"]
}

func TestUploadMetadataUsesBrowserShapeForAllTypes(t *testing.T) {
	for _, name := range []string{"song.m4a", "note.txt", "program.exe", "random.unknownext"} {
		data := decodeUploadMetadata(t, name, time.Now())
		if data["name"] != name {
			t.Fatalf("name = %q, want %q", data["name"], name)
		}
		if _, ok := data["contenttype"]; ok {
			t.Fatalf("%s metadata should not include contenttype", name)
		}
	}
}

func TestUploadMetadataFormatsModificationTimeAsUTC(t *testing.T) {
	tests := []struct {
		name    string
		modTime time.Time
		want    string
	}{
		{
			name:    "known",
			modTime: time.Date(2025, 1, 13, 12, 0, 0, 0, time.FixedZone("UTC+2", 2*60*60)),
			want:    "20250113T100000Z",
		},
		{name: "unknown", modTime: time.Time{}, want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := decodeUploadMetadata(t, "file.txt", test.modTime)["modificationdate"]; got != test.want {
				t.Fatalf("modificationdate = %v, want %v", got, test.want)
			}
		})
	}
}

func TestO2DoesNotAdvertiseETagAsContentHash(t *testing.T) {
	if got := (&Fs{}).Hashes(); got != hash.Set(hash.None) {
		t.Fatalf("Hashes = %v, want none", got)
	}
	if _, err := (&Object{}).Hash(context.Background(), hash.MD5); err != hash.ErrUnsupported {
		t.Fatalf("MD5 error = %v, want %v", err, hash.ErrUnsupported)
	}
}

func TestPrecisionMatchesUploadTimestampFormat(t *testing.T) {
	if got := (&Fs{}).Precision(); got != time.Second {
		t.Fatalf("Precision = %v, want %v", got, time.Second)
	}
}

func TestBackendConfigAllSMSLoginCompletes(t *testing.T) {
	ri, err := fs.Find("o2")
	if err != nil {
		t.Fatal(err)
	}

	clientID, clientSecret, err := oauthClientCredentials()
	if err != nil {
		t.Fatal(err)
	}
	var oauthState string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/authorize":
			query := r.URL.Query()
			for name, want := range map[string]string{
				"response_type":         "code",
				"client_id":             clientID,
				"redirect_uri":          oauthRedirectURL,
				"access_type":           "offline",
				"scope":                 "openid",
				"code_challenge_method": "S256",
				"acr_values":            "2",
			} {
				if got := query.Get(name); got != want {
					t.Fatalf("authorize %s = %q, want %q", name, got, want)
				}
			}
			if query.Get("code_challenge") == "" || query.Get("nonce") == "" || query.Get("state") == "" {
				t.Fatal("authorize request is missing PKCE/state/nonce")
			}
			oauthState = query.Get("state")
			fragment := url.Values{
				"action":      {"login"},
				"client_name": {"O2CLOUD_ANDROID"},
				"client_id":   {clientID},
				"state":       {oauthState},
				"sessionID":   {"session-1"},
				"sessionData": {"data-1"},
				"acr_values":  {"line"},
			}.Encode()
			http.Redirect(w, r, server.URL+"/acceso/#/accessUserPassO2?"+fragment, http.StatusFound)

		case r.URL.Path == "/acceso/":
			_, _ = w.Write([]byte("Mi O2"))

		case r.URL.Path == "/coco-envInfo/env.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"apiGwUrl": server.URL + "/t3/"})

		case r.URL.Path == "/t3/cus/segu/v5/seguCredentialO2s/manageCredentialMobileO2":
			var request struct {
				Mobile      string `json:"mobile"`
				SessionID   string `json:"sessionID"`
				SessionData string `json:"sessionData"`
				ConsumerID  string `json:"consumerId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Mobile != "600111222" || request.SessionID != "session-1" || request.SessionData != "data-1" || request.ConsumerID != "O2CLOUD_ANDROID" {
				t.Fatalf("manage credential request = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"newSessionID": "session-2", "newSessionData": "data-2"})

		case r.URL.Path == "/t3/cus/segu/v5/seguCredentialO2s/verifyCredentialMobileO2":
			var request struct {
				OTP         string `json:"otp"`
				SessionID   string `json:"sessionID"`
				SessionData string `json:"sessionData"`
				Mobile      string `json:"Mobile"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.OTP != "123456" || request.SessionID != "session-2" || request.SessionData != "data-2" || request.Mobile != "600111222" {
				t.Fatalf("verify credential request = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"redirectUri": oauthRedirectURL + "?code=auth-code&state=" + url.QueryEscape(oauthState),
			})

		case r.URL.Path == "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string]string{
				"grant_type":    "authorization_code",
				"code":          "auth-code",
				"redirect_uri":  oauthRedirectURL,
				"client_id":     clientID,
				"client_secret": clientSecret,
			} {
				if got := r.Form.Get(name); got != want {
					t.Fatalf("token %s = %q, want %q", name, got, want)
				}
			}
			if r.Form.Get("code_verifier") == "" {
				t.Fatal("token request is missing code_verifier")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-initial", "refresh_token": "refresh-initial", "expires_in": 3600, "token_type": "Bearer",
			})

		case r.URL.Path == "/sapi/login/oauth" && r.URL.Query().Get("action") == "login":
			credential, found, err := parseOAuthAuthorization(r.Header.Get("Authorization"))
			if err != nil || !found || credential.AccessToken != "access-initial" || credential.RefreshToken != "refresh-initial" {
				t.Fatalf("OAuth login credential = %+v, found=%v, err=%v", credential, found, err)
			}
			rotated, err := oauthAuthorization(Options{
				AccessToken: "access-rotated", RefreshToken: "refresh-rotated", OAuthExpiresIn: "3600", OAuthLastRefreshDate: 12345,
			})
			if err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Authorization", rotated)
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "session-new", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"validationkey": "validation-new", "jsessionid": "session-new",
			}})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	oldAuthorizeURL, oldTokenURL, oldRedirectURL := oauthAuthorizeURL, oauthTokenURL, oauthRedirectURL
	oauthAuthorizeURL = server.URL + "/authorize"
	oauthTokenURL = server.URL + "/token"
	oauthRedirectURL = server.URL + "/ui/html/clientoauth.html"
	defer func() {
		oauthAuthorizeURL, oauthTokenURL, oauthRedirectURL = oldAuthorizeURL, oldTokenURL, oldRedirectURL
	}()

	m := configmap.Simple{"type": "o2", "api_url": server.URL, "upload_url": server.URL}
	choices := configmap.Simple{
		"provider":           "o2",
		"phone_number":       "600 111 222",
		"config_sms_code":    "123456",
		"config_fs_advanced": "false",
	}
	out, err := fs.BackendConfig(context.Background(), "o2test", m, ri, choices, fs.ConfigIn{State: fs.ConfigAll})
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Fatalf("out = %#v", out)
	}
	if got := m["phone_number"]; got != "34600111222" {
		t.Fatalf("phone_number = %q, want normalized phone", got)
	}
	if got := revealIfObscured(m["validation_key"]); got != "validation-new" {
		t.Fatalf("validation_key = %q, want validation-new", got)
	}
	if got := revealIfObscured(m["jsessionid"]); got != "session-new" {
		t.Fatalf("jsessionid = %q, want session-new", got)
	}
	if got := revealIfObscured(m["access_token"]); got != "access-rotated" {
		t.Fatalf("access_token was not rotated")
	}
	if got := revealIfObscured(m["refresh_token"]); got != "refresh-rotated" {
		t.Fatalf("refresh_token was not rotated")
	}
	if got := m["oauth_expires_in"]; got != "3600" {
		t.Fatalf("oauth_expires_in = %q, want 3600", got)
	}
	if got := m["oauth_last_refresh_date"]; got != "12345" {
		t.Fatalf("oauth_last_refresh_date = %q, want 12345", got)
	}
	if got := m["device_id"]; !strings.HasPrefix(got, "fac-") {
		t.Fatalf("device_id = %q, want fac-*", got)
	}
}

func TestMovistarSMSLoginCompletes(t *testing.T) {
	var oauthState string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/authorize":
			query := r.URL.Query()
			for name, want := range map[string]string{
				"response_type":         "code",
				"client_id":             defaultMovistarOAuthClientID,
				"redirect_uri":          server.URL + "/ui/html/clientoauth.html",
				"access_type":           "offline",
				"scope":                 "openid",
				"code_challenge_method": "S256",
				"acr_values":            "2",
				"lang":                  "en",
			} {
				if got := query.Get(name); got != want {
					t.Fatalf("authorize %s = %q, want %q", name, got, want)
				}
			}
			oauthState = query.Get("state")
			fragment := url.Values{
				"action":      {"login"},
				"consumer_id": {"MCLOUD_APP"},
				"client_id":   {defaultMovistarOAuthClientID},
				"state":       {oauthState},
				"sessionID":   {"session-1"},
				"sessionData": {"data-1"},
				"acr_values":  {"2"},
			}.Encode()
			http.Redirect(w, r, server.URL+"/segu-loginApp/#/accessUserPass?"+fragment, http.StatusFound)

		case r.URL.Path == "/segu-loginApp/":
			_, _ = w.Write([]byte("Movistar"))

		case r.URL.Path == "/coco-envInfo/env.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"apiGwUrl": server.URL + "/t3/"})

		case r.URL.Path == "/t3/cus/segu/v6/loginCredentialLAs/manageCredentialMobile":
			var request struct {
				ConsumerID  string `json:"consumerId"`
				Mobile      string `json:"Mobile"`
				SessionID   string `json:"sessionId"`
				SessionData string `json:"sessionData"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.ConsumerID != "MCLOUD_APP" || request.Mobile != "600111222" || request.SessionID != "session-1" || request.SessionData != "data-1" {
				t.Fatalf("manage credential request = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"newSessionID": "session-2", "newSessionData": "data-2"})

		case r.URL.Path == "/t3/cus/segu/v6/loginCredentialLAs/verifyCredentialMobile":
			var request struct {
				OTP         string `json:"otp"`
				SessionID   string `json:"sessionID"`
				SessionData string `json:"sessionData"`
				Mobile      string `json:"Mobile"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.OTP != "876709" || request.SessionID != "session-2" || request.SessionData != "data-2" || request.Mobile != "600111222" {
				t.Fatalf("verify credential request = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"redirectUri": server.URL + "/ui/html/clientoauth.html?code=auth-code&state=" + url.QueryEscape(oauthState),
			})

		case r.URL.Path == "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string]string{
				"grant_type":    "authorization_code",
				"code":          "auth-code",
				"redirect_uri":  server.URL + "/ui/html/clientoauth.html",
				"client_id":     defaultMovistarOAuthClientID,
				"client_secret": defaultMovistarOAuthClientSecret,
			} {
				if got := r.Form.Get(name); got != want {
					t.Fatalf("token %s = %q, want %q", name, got, want)
				}
			}
			if r.Form.Get("code_verifier") == "" {
				t.Fatal("token request is missing code_verifier")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-initial", "refresh_token": "refresh-initial", "expires_in": 3600, "token_type": "Bearer",
			})

		case r.URL.Path == "/sapi/login/oauth" && r.URL.Query().Get("action") == "login":
			credential, found, err := parseOAuthAuthorization(r.Header.Get("Authorization"))
			if err != nil || !found || credential.AccessToken != "access-initial" || credential.RefreshToken != "refresh-initial" || credential.Platform != movistarOAuthPlatform {
				t.Fatalf("OAuth login credential = %+v, found=%v, err=%v", credential, found, err)
			}
			profile, err := (Options{Provider: providerMovistar}).provider()
			if err != nil {
				t.Fatal(err)
			}
			rotated, err := oauthAuthorizationForProfile(Options{
				Provider: providerMovistar, AccessToken: "access-rotated", RefreshToken: "refresh-rotated", OAuthExpiresIn: "3600", OAuthLastRefreshDate: 12345,
			}, profile)
			if err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Authorization", rotated)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"validationkey": "validation-new", "jsessionid": "session-new",
			}})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldAuthorizeURL, oldTokenURL, oldRedirectURL := movistarOAuthAuthorizeURL, movistarOAuthTokenURL, movistarOAuthRedirectURL
	movistarOAuthAuthorizeURL = server.URL + "/authorize"
	movistarOAuthTokenURL = server.URL + "/token"
	movistarOAuthRedirectURL = server.URL + "/ui/html/clientoauth.html"
	defer func() {
		movistarOAuthAuthorizeURL, movistarOAuthTokenURL, movistarOAuthRedirectURL = oldAuthorizeURL, oldTokenURL, oldRedirectURL
	}()

	started, err := startSMSAuth(context.Background(), Options{
		Provider:    providerMovistar,
		PhoneNumber: "34600111222",
		APIURL:      server.URL,
		UploadURL:   server.URL,
		DeviceID:    "mox-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := finishSMSAuth(context.Background(), started, "876709")
	if err != nil {
		t.Fatal(err)
	}
	if result.ValidationKey != "validation-new" || result.JSessionID != "session-new" || result.AccessToken != "access-rotated" || result.RefreshToken != "refresh-rotated" {
		t.Fatalf("result = %#v", result)
	}
}

func TestBackendConfigReportsSMSStartError(t *testing.T) {
	ri, err := fs.Find("o2")
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/authorize":
			fragment := url.Values{"client_name": {"O2CLOUD_ANDROID"}, "state": {r.URL.Query().Get("state")}, "sessionID": {"session-1"}, "sessionData": {"data-1"}}.Encode()
			http.Redirect(w, r, server.URL+"/acceso/#/accessUserPassO2?"+fragment, http.StatusFound)
		case r.URL.Path == "/acceso/":
			_, _ = w.Write([]byte("Mi O2"))
		case r.URL.Path == "/coco-envInfo/env.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"apiGwUrl": server.URL + "/t3/"})
		case r.URL.Path == "/t3/cus/segu/v5/seguCredentialO2s/manageCredentialMobileO2":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"faultDetail": map[string]string{
				"errorId":          "AUTH-TEST",
				"errorDescription": "SMS login rejected",
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	oldAuthorizeURL, oldRedirectURL := oauthAuthorizeURL, oauthRedirectURL
	oauthAuthorizeURL = server.URL + "/authorize"
	oauthRedirectURL = server.URL + "/ui/html/clientoauth.html"
	defer func() { oauthAuthorizeURL, oauthRedirectURL = oldAuthorizeURL, oldRedirectURL }()

	m := configmap.Simple{"type": "o2", "api_url": server.URL, "upload_url": server.URL}
	choices := configmap.Simple{
		"provider":           "o2",
		"phone_number":       "600 111 222",
		"config_fs_advanced": "false",
	}
	_, err = fs.BackendConfig(context.Background(), "o2test", m, ri, choices, fs.ConfigIn{State: fs.ConfigAll})
	if err == nil {
		t.Fatal("expected SMS start error")
	}
	if got, want := err.Error(), "O2 SMS authorization failed: AUTH-TEST: SMS login rejected"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestFinishSMSAuthRejectsMismatchedOAuthState(t *testing.T) {
	callbackRequested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cus/segu/v5/seguCredentialO2s/verifyCredentialMobileO2":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"redirectUri": "http://" + r.Host + "/ui/html/clientoauth.html?code=auth-code&state=wrong-state",
			})
		default:
			callbackRequested = true
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := finishSMSAuth(context.Background(), authState{
		APIURL:      server.URL,
		DeviceID:    "fac-device",
		LoginURL:    server.URL + "/acceso/",
		RedirectURL: server.URL + "/ui/html/clientoauth.html",
		OTPAPIURL:   server.URL,
		Mobile:      "600000000",
		OAuthState:  "expected-state",
		SessionID:   "session-id",
		SessionData: "session-data",
	}, "123456")
	if err == nil || err.Error() != "O2 SMS login returned an invalid OAuth state" {
		t.Fatalf("error = %v, want invalid OAuth state", err)
	}
	if callbackRequested {
		t.Fatal("OAuth callback was requested after a state mismatch")
	}
}

func testOAuthOptions(apiURL string) Options {
	return Options{
		ValidationKey:        "validation-old",
		JSessionID:           "session-old",
		DeviceID:             "fac-test-device",
		AccessToken:          "access-old",
		RefreshToken:         "refresh-old",
		OAuthExpiresIn:       "3600",
		OAuthLastRefreshDate: time.Now().UnixMilli(),
		APIURL:               apiURL,
		UploadURL:            apiURL,
		Enc:                  encoder.Display | encoder.EncodeInvalidUtf8,
	}
}

func TestAPIRenewsAndroidOAuthSessionAndSavesIt(t *testing.T) {
	ctx := context.Background()
	var rootRequests, loginRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sapi/login/oauth" && r.URL.Query().Get("action") == "login":
			loginRequests++
			if r.Method != http.MethodPost {
				t.Fatalf("OAuth login method = %s, want POST", r.Method)
			}
			credential, found, err := parseOAuthAuthorization(r.Header.Get("Authorization"))
			if err != nil || !found || credential.AccessToken != "access-old" || credential.RefreshToken != "refresh-old" {
				t.Fatalf("OAuth login credential = %+v, found=%v, err=%v", credential, found, err)
			}
			rotated, err := oauthAuthorization(Options{
				AccessToken: "access-new", RefreshToken: "refresh-new", OAuthExpiresIn: "7200", OAuthLastRefreshDate: 987654321,
			})
			if err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Authorization", rotated)
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "session-new", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"validationkey": "validation-new", "jsessionid": "session-new",
			}})

		case r.URL.Path == "/sapi/media/folder/root" && r.URL.Query().Get("action") == "get":
			rootRequests++
			switch rootRequests {
			case 1:
				if got := r.URL.Query().Get("validationkey"); got != "validation-old" {
					t.Fatalf("first validationkey = %q, want validation-old", got)
				}
				if _, err := r.Cookie("validationKey"); err == nil {
					t.Fatal("legacy validationKey cookie was sent")
				}
				if got, err := r.Cookie("JSESSIONID"); err != nil || got.Value != "session-old" {
					t.Fatalf("first JSESSIONID = %v, %v; want session-old", got, err)
				}
				credential, found, err := parseOAuthAuthorization(r.Header.Get("Authorization"))
				if err != nil || !found || credential.AccessToken != "access-old" || credential.RefreshToken != "refresh-old" {
					t.Fatalf("first OAuth credential = %+v, found=%v, err=%v", credential, found, err)
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, "<html>expired</html>")
			case 2, 3:
				if got := r.URL.Query().Get("validationkey"); got != "validation-new" {
					t.Fatalf("renewed validationkey = %q, want validation-new", got)
				}
				if _, err := r.Cookie("validationKey"); err == nil {
					t.Fatal("legacy validationKey cookie was sent after renewal")
				}
				if got, err := r.Cookie("JSESSIONID"); err != nil || got.Value != "session-new" {
					t.Fatalf("renewed JSESSIONID = %v, %v; want session-new", got, err)
				}
				credential, found, err := parseOAuthAuthorization(r.Header.Get("Authorization"))
				if err != nil || !found || credential.AccessToken != "access-new" || credential.RefreshToken != "refresh-new" {
					t.Fatalf("renewed OAuth credential = %+v, found=%v, err=%v", credential, found, err)
				}
				id := int64(42)
				if rootRequests == 3 {
					id = 43
				}
				_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Folders: []api.Folder{{Name: "/", ID: id}}}})
			default:
				t.Fatalf("unexpected root request %d", rootRequests)
			}

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	m := configmap.Simple{"phone_number": "34600111222", "api_url": server.URL, "upload_url": server.URL}
	f := &Fs{
		name:   "o2test",
		opt:    testOAuthOptions(server.URL),
		m:      m,
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}

	id, err := f.readRootFolderID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id != 42 {
		t.Fatalf("root id = %d, want 42", id)
	}
	if got := revealIfObscured(m["validation_key"]); got != "validation-new" {
		t.Fatalf("saved validation_key = %q, want validation-new", got)
	}
	if got := revealIfObscured(m["jsessionid"]); got != "session-new" {
		t.Fatalf("saved jsessionid = %q, want session-new", got)
	}
	if got := revealIfObscured(m["access_token"]); got != "access-new" {
		t.Fatalf("saved access_token = %q, want access-new", got)
	}
	if got := revealIfObscured(m["refresh_token"]); got != "refresh-new" {
		t.Fatalf("saved refresh_token = %q, want refresh-new", got)
	}
	if got := m["device_id"]; got != "fac-test-device" {
		t.Fatalf("saved device_id = %q, want fac-test-device", got)
	}

	opt, err := readOptions(m)
	if err != nil {
		t.Fatal(err)
	}
	f2 := &Fs{
		name:   "o2test",
		opt:    opt,
		m:      m,
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	id, err = f2.readRootFolderID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id != 43 {
		t.Fatalf("second Fs root id = %d, want 43", id)
	}
	if loginRequests != 1 {
		t.Fatalf("OAuth login requests = %d, want 1", loginRequests)
	}
}

func TestAPIReportsRejectedAndroidRefreshToken(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sapi/media/folder/root" && r.URL.Path != "/sapi/login/oauth" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(api.Envelope{Error: &api.Error{Code: "SEC-1001", Message: "invalid OAuth credentials"}})
	}))
	defer server.Close()

	f := &Fs{
		name:   "o2test",
		opt:    testOAuthOptions(server.URL),
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}

	_, err := f.readRootFolderID(ctx)
	if err == nil || !strings.Contains(err.Error(), `rclone config reconnect o2test:`) {
		t.Fatalf("error = %v, want reconnect instruction", err)
	}
}

func TestOpenNormalizesRangeOptions(t *testing.T) {
	const payload = "0123456789"
	for _, test := range []struct {
		name      string
		options   []fs.OpenOption
		wantRange string
		wantBody  string
	}{
		{
			name:      "suffix range",
			options:   []fs.OpenOption{&fs.RangeOption{Start: -1, End: 4}},
			wantRange: "bytes=6-9",
			wantBody:  payload[6:],
		},
		{
			name:      "seek",
			options:   []fs.OpenOption{&fs.SeekOption{Offset: 3}},
			wantRange: "bytes=3-9",
			wantBody:  payload[3:],
		},
		{
			name:      "chunked reader range",
			options:   []fs.OpenOption{&fs.HashesOption{Hashes: hash.Set(hash.None)}, &fs.RangeOption{Start: 2, End: 5}},
			wantRange: "bytes=2-5",
			wantBody:  payload[2:6],
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			var gotRange string
			var calledDownload bool
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/sapi/media":
					_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Media: []api.Media{{
						ID:   "123",
						Name: "file.txt",
						Size: int64(len(payload)),
						URL:  server.URL + "/download",
					}}}})
				case "/download":
					calledDownload = true
					gotRange = r.Header.Get("Range")
					if gotRange != test.wantRange {
						t.Fatalf("Range = %q, want %s", gotRange, test.wantRange)
					}
					w.WriteHeader(http.StatusPartialContent)
					_, _ = w.Write([]byte(test.wantBody))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			f := &Fs{
				name: "o2test",
				opt: Options{
					ValidationKey: "24553931775f412a57804d272b305848",
					JSessionID:    "2D4F6F492842ADB18DEB929ACE9984E8.1i221",
					DeviceID:      "web-test-device",
					APIURL:        server.URL,
					UploadURL:     server.URL,
					Enc:           encoder.Display | encoder.EncodeInvalidUtf8,
				},
				client: server.Client(),
				pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
			}
			o := &Object{
				fs:     f,
				remote: "file.txt",
				id:     "123",
				size:   int64(len(payload)),
			}

			rc, err := o.Open(ctx, test.options...)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.CheckClose(rc, &err)
			got, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.wantBody {
				t.Fatalf("body = %q, want %q", got, test.wantBody)
			}
			if !calledDownload {
				t.Fatal("download endpoint was not called")
			}
		})
	}
}

func TestVFSReadAtUsesRangeOptions(t *testing.T) {
	const payload = "0123456789"
	ctx := context.Background()
	var ranges []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sapi/media/folder" && r.URL.Query().Get("action") == "list":
			_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Folders: []api.Folder{}}})
		case r.URL.Path == "/sapi/media" && r.URL.Query().Get("action") == "get":
			_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Media: []api.Media{{
				ID:   "123",
				Name: "file.txt",
				Size: int64(len(payload)),
				URL:  server.URL + "/download",
			}}}})
		case r.URL.Path == "/download":
			gotRange := r.Header.Get("Range")
			ranges = append(ranges, gotRange)
			switch gotRange {
			case "bytes=0-3":
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte(payload[:4]))
			case "bytes=9-9":
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte(payload[9:]))
			default:
				t.Fatalf("unexpected Range = %q", gotRange)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := &Fs{
		name:   "o2test",
		opt:    testOAuthOptions(server.URL),
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
		ReadMimeType:            true,
		Purge:                   f.Purge,
		Move:                    f.Move,
		About:                   f.About,
	}).Fill(ctx, f)
	f.dirCache = dircache.New("", "1", f)

	opt := vfscommon.Opt
	opt.ChunkSize = 4
	opt.ChunkSizeLimit = 4
	opt.ReadWait = 0
	v := vfs.New(ctx, f, &opt)
	defer v.Shutdown()

	handle, err := v.OpenFile("file.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.CheckClose(handle, &err)

	buf := make([]byte, 1)
	n, err := handle.ReadAt(buf, 9)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || string(buf) != payload[9:] {
		t.Fatalf("ReadAt = %d, %q; want 1, %q", n, buf, payload[9:])
	}
	if len(ranges) != 2 || ranges[0] != "bytes=0-3" || ranges[1] != "bytes=9-9" {
		t.Fatalf("ranges = %#v, want [bytes=0-3 bytes=9-9]", ranges)
	}
}

func TestListMediaPaginates(t *testing.T) {
	ctx := context.Background()
	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sapi/media" || r.URL.Query().Get("action") != "get" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("folderid"); got != "42" {
			t.Fatalf("folderid = %q, want 42", got)
		}
		if got := r.URL.Query().Get("limit"); got != "200" {
			t.Fatalf("limit = %q, want 200", got)
		}
		offset := r.URL.Query().Get("offset")
		offsets = append(offsets, offset)
		media := make([]api.Media, 0, listPageSize)
		switch offset {
		case "":
			for i := range listPageSize {
				media = append(media, api.Media{ID: fmt.Sprintf("%d", i), Name: fmt.Sprintf("file-%03d", i)})
			}
		case "200":
			for i := range listPageSize {
				media = append(media, api.Media{ID: fmt.Sprintf("%d", 200+i), Name: fmt.Sprintf("file-%03d", 200+i)})
			}
		case "400":
			media = append(media, api.Media{ID: "400", Name: "file-400"})
		default:
			t.Fatalf("unexpected offset %q", offset)
		}
		_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Media: media}})
	}))
	defer server.Close()

	f := &Fs{opt: testOAuthOptions(server.URL), client: server.Client(), pacer: fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))}
	media, err := f.listMedia(ctx, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(media) != 401 {
		t.Fatalf("media count = %d, want 401", len(media))
	}
	if !slices.Equal(offsets, []string{"", "200", "400"}) {
		t.Fatalf("offsets = %#v, want [\"\" \"200\" \"400\"]", offsets)
	}
}

func TestListFoldersPaginates(t *testing.T) {
	ctx := context.Background()
	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sapi/media/folder" || r.URL.Query().Get("action") != "list" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("parentid"); got != "42" {
			t.Fatalf("parentid = %q, want 42", got)
		}
		if got := r.URL.Query().Get("limit"); got != "200" {
			t.Fatalf("limit = %q, want 200", got)
		}
		offset := r.URL.Query().Get("offset")
		offsets = append(offsets, offset)
		folders := make([]api.Folder, 0, listPageSize)
		switch offset {
		case "":
			for i := range listPageSize {
				folders = append(folders, api.Folder{ID: int64(i), Name: fmt.Sprintf("folder-%03d", i)})
			}
		case "200":
			folders = append(folders, api.Folder{ID: 200, Name: "folder-200"})
		default:
			t.Fatalf("unexpected offset %q", offset)
		}
		_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Folders: folders}})
	}))
	defer server.Close()

	f := &Fs{opt: testOAuthOptions(server.URL), client: server.Client(), pacer: fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))}
	folders, err := f.listFolders(ctx, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(folders) != 201 {
		t.Fatalf("folder count = %d, want 201", len(folders))
	}
	if !slices.Equal(offsets, []string{"", "200"}) {
		t.Fatalf("offsets = %#v, want [\"\" \"200\"]", offsets)
	}
}

func TestMoveUsesMediaTypeSpecificSaveMetadata(t *testing.T) {
	ctx := context.Background()
	var saveRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sapi/media/folder" && r.URL.Query().Get("action") == "list":
			if got := r.URL.Query().Get("parentid"); got != "1" {
				t.Fatalf("folder list parentid=%q, want 1", got)
			}
			_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Folders: []api.Folder{{Name: "dest", ID: 20, ParentID: 1}}}})

		case r.URL.Path == "/sapi/upload/video" && r.URL.Query().Get("action") == "save-metadata":
			saveRequests++
			if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/x-www-form-urlencoded") {
				t.Fatalf("Content-Type = %q, want form-urlencoded", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Data struct {
					ID       int64  `json:"id"`
					Name     string `json:"name"`
					FolderID int64  `json:"folderid"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(r.Form.Get("data")), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Data.ID != 123 || payload.Data.Name != "video.mkv" || payload.Data.FolderID != 20 {
				t.Fatalf("media metadata payload = %+v, want id=123 name=video.mkv folderid=20", payload.Data)
			}
			_, _ = w.Write([]byte(`{"success":"true","id":"123"}`))

		case r.URL.Path == "/sapi/media" && r.URL.Query().Get("action") == "get":
			_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Media: []api.Media{{
				ID:        "123",
				Name:      "video.mkv",
				MediaType: "video",
				Folder:    20,
				Size:      10,
			}}}})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := &Fs{
		name: "o2test",
		root: "",
		opt: Options{
			ValidationKey: "24553931775f412a57804d272b305848",
			JSessionID:    "2D4F6F492842ADB18DEB929ACE9984E8.1i221",
			DeviceID:      "web-test-device",
			APIURL:        server.URL,
			UploadURL:     server.URL,
			Enc:           encoder.Display | encoder.EncodeInvalidUtf8,
		},
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.dirCache = dircache.New("", "1", f)
	src := &Object{
		fs:        f,
		remote:    "src/video.mkv",
		id:        "123",
		size:      10,
		mediaType: "video",
	}

	obj, err := f.Move(ctx, src, "dest/video.mkv")
	if err != nil {
		t.Fatal(err)
	}
	if obj.(*Object).mediaType != "video" {
		t.Fatalf("moved object mediaType = %q, want video", obj.(*Object).mediaType)
	}
	if saveRequests != 1 {
		t.Fatalf("save requests = %d, want 1", saveRequests)
	}
}

func TestUpdateUploadsWithTemporaryNameThenRenamesToOriginal(t *testing.T) {
	ctx := context.Background()
	const payload = "updated payload"
	var uploadRequests, deleteRequests, saveRequests, listRequests int
	var temporaryUploadName string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sapi/upload" && r.URL.Query().Get("action") == "save":
			uploadRequests++
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				t.Fatal(err)
			}
			form, err := multipart.NewReader(bytes.NewReader(body), params["boundary"]).ReadForm(int64(len(body)))
			if err != nil {
				t.Fatal(err)
			}
			if got := len(form.Value["data"]); got != 1 {
				t.Fatalf("upload data fields = %d, want 1", got)
			}
			var metadata struct {
				Data struct {
					Name     string `json:"name"`
					FolderID int64  `json:"folderid"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(form.Value["data"][0]), &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.Data.Name == "hello.txt" {
				t.Fatal("update uploaded replacement with colliding original name")
			}
			if !strings.HasPrefix(metadata.Data.Name, "hello.txt.rclone-upload-") {
				t.Fatalf("temporary upload name = %q, want hello.txt.rclone-upload-*", metadata.Data.Name)
			}
			if metadata.Data.FolderID != 1 {
				t.Fatalf("temporary upload folderid = %d, want 1", metadata.Data.FolderID)
			}
			temporaryUploadName = metadata.Data.Name
			files := form.File["file"]
			if len(files) != 1 {
				t.Fatalf("upload file parts = %d, want 1", len(files))
			}
			file, err := files[0].Open()
			if err != nil {
				t.Fatal(err)
			}
			defer fs.CheckClose(file, &err)
			gotPayload, err := io.ReadAll(file)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotPayload) != payload {
				t.Fatalf("upload payload = %q, want %q", gotPayload, payload)
			}
			_ = json.NewEncoder(w).Encode(api.UploadResponse{Success: "true", ID: "456", Status: "V", Type: "file"})

		case r.URL.Path == "/sapi/media/file" && r.URL.Query().Get("action") == "delete":
			deleteRequests++
			if got := r.URL.Query().Get("softdelete"); got != "false" {
				t.Fatalf("update cleanup softdelete = %q, want false", got)
			}
			var request struct {
				Data struct {
					Files []int64 `json:"files"`
				} `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if len(request.Data.Files) != 1 || request.Data.Files[0] != 123 {
				t.Fatalf("deleted files = %#v, want [123]", request.Data.Files)
			}
			if temporaryUploadName == "" {
				t.Fatal("old object was deleted before temporary replacement upload")
			}
			_ = json.NewEncoder(w).Encode(api.Envelope{Success: "true"})

		case r.URL.Path == "/sapi/upload/file" && r.URL.Query().Get("action") == "save-metadata":
			saveRequests++
			if deleteRequests == 0 {
				t.Fatal("replacement was renamed before old object was deleted")
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			var request struct {
				Data struct {
					ID       int64  `json:"id"`
					Name     string `json:"name"`
					FolderID int64  `json:"folderid"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(r.Form.Get("data")), &request); err != nil {
				t.Fatal(err)
			}
			if request.Data.ID != 456 || request.Data.Name != "hello.txt" || request.Data.FolderID != 1 {
				t.Fatalf("save metadata payload = %+v, want id=456 name=hello.txt folderid=1", request.Data)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"success": "true", "id": "456"})

		case r.URL.Path == "/sapi/media" && r.URL.Query().Get("action") == "get":
			listRequests++
			if saveRequests == 0 {
				t.Fatal("updated object was listed before save-metadata")
			}
			_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Media: []api.Media{{
				ID:               "456",
				Name:             "hello.txt",
				MediaType:        "file",
				Folder:           1,
				Size:             int64(len(payload)),
				ModificationDate: time.Now().UnixMilli(),
			}}}})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := &Fs{
		name:   "o2test",
		root:   "",
		opt:    testOAuthOptions(server.URL),
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.dirCache = dircache.New("", "1", f)

	existing := &Object{fs: f, remote: "hello.txt", id: "123", size: 3, mediaType: "file"}
	src := object.NewStaticObjectInfo("hello.txt", time.Now(), int64(len(payload)), true, nil, f)
	if err := existing.Update(ctx, strings.NewReader(payload), src); err != nil {
		t.Fatal(err)
	}
	if existing.remote != "hello.txt" || existing.id != "456" || existing.size != int64(len(payload)) {
		t.Fatalf("updated object = remote %q id %q size %d, want hello.txt/456/%d", existing.remote, existing.id, existing.size, len(payload))
	}
	if uploadRequests != 1 || deleteRequests != 1 || saveRequests != 1 || listRequests != 1 {
		t.Fatalf("requests upload/delete/save/list = %d/%d/%d/%d, want 1/1/1/1", uploadRequests, deleteRequests, saveRequests, listRequests)
	}
}

func TestUpdateKeepsOldObjectIfTemporaryUploadMetadataUnavailable(t *testing.T) {
	ctx := context.Background()
	var deletedIDs []int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sapi/upload" && r.URL.Query().Get("action") == "save":
			// Deliberately omit Type so Update must resolve metadata before deleting
			// the old object.
			_ = json.NewEncoder(w).Encode(api.UploadResponse{Success: "true", ID: "456", Status: "V"})

		case r.URL.Path == "/sapi/media" && r.URL.Query().Get("action") == "get":
			http.Error(w, "metadata unavailable", http.StatusInternalServerError)

		case r.URL.Path == "/sapi/media/file" && r.URL.Query().Get("action") == "delete":
			if got := r.URL.Query().Get("softdelete"); got != "false" {
				t.Fatalf("temporary cleanup softdelete = %q, want false", got)
			}
			var request struct {
				Data struct {
					Files []int64 `json:"files"`
				} `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			deletedIDs = append(deletedIDs, request.Data.Files...)
			_ = json.NewEncoder(w).Encode(api.Envelope{Success: "true"})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := &Fs{
		name:   "o2test",
		root:   "",
		opt:    testOAuthOptions(server.URL),
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.dirCache = dircache.New("", "1", f)

	existing := &Object{fs: f, remote: "hello.txt", id: "123", size: 3}
	src := object.NewStaticObjectInfo("hello.txt", time.Now(), int64(len("payload")), true, nil, f)
	if err := existing.Update(ctx, strings.NewReader("payload"), src); err == nil {
		t.Fatal("expected update error")
	}
	if existing.remote != "hello.txt" || existing.id != "123" {
		t.Fatalf("old object changed to remote %q id %q, want hello.txt/123", existing.remote, existing.id)
	}
	if len(deletedIDs) != 1 || deletedIDs[0] != 456 {
		t.Fatalf("deleted IDs = %#v, want only temporary object [456]", deletedIDs)
	}
}

func TestRemoveUsesTrashOption(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name           string
		useTrash       bool
		wantSoftDelete string
	}{
		{name: "trash", useTrash: true, wantSoftDelete: "true"},
		{name: "hard delete", useTrash: false, wantSoftDelete: "false"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/sapi/media/file" || r.URL.Query().Get("action") != "delete" {
					http.NotFound(w, r)
					return
				}
				if got := r.URL.Query().Get("softdelete"); got != test.wantSoftDelete {
					t.Fatalf("softdelete = %q, want %s", got, test.wantSoftDelete)
				}
				var request struct {
					Data struct {
						Files []int64 `json:"files"`
					} `json:"data"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				if len(request.Data.Files) != 1 || request.Data.Files[0] != 123 {
					t.Fatalf("deleted files = %#v, want [123]", request.Data.Files)
				}
				_ = json.NewEncoder(w).Encode(api.Envelope{Success: "true"})
			}))
			defer server.Close()

			f := &Fs{
				name:   "o2test",
				opt:    testOAuthOptions(server.URL),
				client: server.Client(),
				pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
			}
			f.opt.UseTrash = test.useTrash
			obj := &Object{fs: f, remote: "hello.txt", id: "123"}
			if err := obj.Remove(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRemoveBatchesDeletesByTrashMode(t *testing.T) {
	ctx := context.Background()
	type deleteRequest struct {
		softdelete string
		files      []int64
	}
	var mu sync.Mutex
	var requests []deleteRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sapi/media/file" || r.URL.Query().Get("action") != "delete" {
			http.NotFound(w, r)
			return
		}
		var request struct {
			Data struct {
				Files []int64 `json:"files"`
			} `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		requests = append(requests, deleteRequest{softdelete: r.URL.Query().Get("softdelete"), files: request.Data.Files})
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(api.Envelope{Success: "true"})
	}))
	defer server.Close()

	f := &Fs{
		name:   "o2test",
		opt:    testOAuthOptions(server.URL),
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	if err := f.initDeleteBatcher(ctx); err != nil {
		t.Fatal(err)
	}
	defer f.deleteBatcher.Shutdown()

	items := []struct {
		id       string
		remote   string
		useTrash bool
	}{
		{id: "101", remote: "trash-1", useTrash: true},
		{id: "102", remote: "trash-2", useTrash: true},
		{id: "103", remote: "trash-3", useTrash: true},
		{id: "201", remote: "hard-1", useTrash: false},
		{id: "202", remote: "hard-2", useTrash: false},
	}
	var wg sync.WaitGroup
	for _, item := range items {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			obj := &Object{fs: f, remote: item.remote, id: item.id}
			if err := obj.removeBatched(ctx, item.useTrash); err != nil {
				t.Errorf("removeBatched(%s) failed: %v", item.id, err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("delete requests = %#v, want 2 batched requests", requests)
	}
	got := map[string][]int64{}
	for _, request := range requests {
		got[request.softdelete] = append(got[request.softdelete], request.files...)
	}
	slices.Sort(got["true"])
	slices.Sort(got["false"])
	if !slices.Equal(got["true"], []int64{101, 102, 103}) {
		t.Fatalf("soft-delete files = %#v, want [101 102 103]", got["true"])
	}
	if !slices.Equal(got["false"], []int64{201, 202}) {
		t.Fatalf("hard-delete files = %#v, want [201 202]", got["false"])
	}
}

func TestDirMoveUsesFolderSaveMetadata(t *testing.T) {
	ctx := context.Background()
	var saveRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sapi/media/folder" && r.URL.Query().Get("action") == "list":
			switch r.URL.Query().Get("parentid") {
			case "1":
				_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Folders: []api.Folder{
					{Name: "source", ID: 10, ParentID: 1},
					{Name: "dest", ID: 20, ParentID: 1},
				}}})
			case "20":
				_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Folders: []api.Folder{}}})
			default:
				t.Fatalf("unexpected folder list parentid=%q", r.URL.Query().Get("parentid"))
			}

		case r.URL.Path == "/sapi/media/folder" && r.URL.Query().Get("action") == "save":
			saveRequests++
			if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/x-www-form-urlencoded") {
				t.Fatalf("Content-Type = %q, want form-urlencoded", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Data struct {
					ID       int64  `json:"id"`
					Name     string `json:"name"`
					ParentID int64  `json:"parentid"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(r.Form.Get("data")), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Data.ID != 10 || payload.Data.Name != "moved" || payload.Data.ParentID != 20 {
				t.Fatalf("folder metadata payload = %+v, want id=10 name=moved parentid=20", payload.Data)
			}
			_ = json.NewEncoder(w).Encode(api.Envelope{Success: "true", Data: api.Data{Folder: &api.Folder{Name: "moved", ID: 10, ParentID: 20}}})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := &Fs{
		name: "o2test",
		root: "",
		opt: Options{
			ValidationKey: "24553931775f412a57804d272b305848",
			JSessionID:    "2D4F6F492842ADB18DEB929ACE9984E8.1i221",
			DeviceID:      "web-test-device",
			APIURL:        server.URL,
			UploadURL:     server.URL,
			Enc:           encoder.Display | encoder.EncodeInvalidUtf8,
		},
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.dirCache = dircache.New("", "1", f)

	if err := f.DirMove(ctx, f, "source", "dest/moved"); err != nil {
		t.Fatal(err)
	}
	if saveRequests != 1 {
		t.Fatalf("save requests = %d, want 1", saveRequests)
	}
	if _, ok := f.dirCache.Get("source"); ok {
		t.Fatal("source directory should be flushed from dir cache after move")
	}
}

func TestUploadSendsKnownLengthMultipartBody(t *testing.T) {
	const payload = "payload"

	var uploadRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sapi/upload" || r.URL.Query().Get("action") != "save" {
			t.Fatalf("unexpected request %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		uploadRequests++
		if r.ContentLength <= int64(len(payload)) {
			t.Fatalf("ContentLength = %d, want multipart body with known length", r.ContentLength)
		}
		if len(r.TransferEncoding) != 0 {
			t.Fatalf("TransferEncoding = %#v, want no chunked transfer", r.TransferEncoding)
		}
		cookies := r.Cookies()
		if len(cookies) != 1 || cookies[0].Name != "JSESSIONID" || cookies[0].Value != "session-old" {
			t.Fatalf("upload cookies = %#v, want JSESSIONID only", cookies)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(body)) != r.ContentLength {
			t.Fatalf("body length = %d, want ContentLength %d", len(body), r.ContentLength)
		}

		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Fatal(err)
		}
		if mediaType != "multipart/form-data" {
			t.Fatalf("Content-Type = %q, want multipart/form-data", mediaType)
		}
		form, err := multipart.NewReader(bytes.NewReader(body), params["boundary"]).ReadForm(int64(len(body)))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(form.Value["data"]); got != 1 {
			t.Fatalf("data fields = %d, want 1", got)
		}
		files := form.File["file"]
		if len(files) != 1 {
			t.Fatalf("file parts = %d, want 1", len(files))
		}
		if got := files[0].Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Fatalf("file part Content-Type = %q, want text/plain; charset=utf-8", got)
		}
		file, err := files[0].Open()
		if err != nil {
			t.Fatal(err)
		}
		defer fs.CheckClose(file, &err)
		gotPayload, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotPayload) != payload {
			t.Fatalf("file payload = %q, want %q", gotPayload, payload)
		}

		_ = json.NewEncoder(w).Encode(api.UploadResponse{Success: "true", ID: "123", Status: "V", ETag: "etag-1"})
	}))
	defer server.Close()

	ctx := context.Background()
	f := &Fs{
		name:   "o2test",
		opt:    testOAuthOptions(server.URL),
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.dirCache = dircache.New("", "1", f)

	src := object.NewStaticObjectInfo("upload.txt", time.Now(), int64(len(payload)), true, nil, f)
	obj, err := f.upload(ctx, strings.NewReader(payload), src)
	if err != nil {
		t.Fatal(err)
	}
	gotObj := obj.(*Object)
	if gotObj.id != "123" || gotObj.size != int64(len(payload)) {
		t.Fatalf("uploaded object = id %q size %d", gotObj.id, gotObj.size)
	}
	if uploadRequests != 1 {
		t.Fatalf("upload requests = %d, want 1", uploadRequests)
	}
}

func TestUploadRequestAlwaysUsesAsync(t *testing.T) {
	ctx := context.Background()
	f := &Fs{
		opt: Options{
			ValidationKey:  "validation",
			JSessionID:     "session",
			DeviceID:       "fac-test-device",
			AccessToken:    "access",
			RefreshToken:   "refresh",
			OAuthExpiresIn: "3600",
			APIURL:         "https://cloud.o2online.es",
			UploadURL:      "https://upload.cloud.o2online.es",
		},
	}

	req, err := f.newUploadRequest(ctx, []byte(`{"data":{}}`), "small.bin", 1, "application/octet-stream", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.URL.Query().Get("acceptasynchronous"); got != "true" {
		t.Fatalf("acceptasynchronous = %q, want true", got)
	}
}

func TestUploadBodyUsesGenericFileContentType(t *testing.T) {
	for _, test := range []struct {
		name     string
		mimeType string
		want     string
	}{
		{name: "song.m4a", mimeType: "audio/mp4", want: "audio/mp4"},
		{name: "note.txt", mimeType: "text/plain", want: "text/plain"},
		{name: "program.exe", mimeType: "application/x-msdownload", want: "application/x-msdownload"},
		{name: "random.unknownext", mimeType: "", want: "application/octet-stream"},
	} {
		body, contentType, _, err := newUploadBody([]byte(`{"data":{}}`), test.name, int64(len("payload")), test.mimeType, strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		_, params, err := mime.ParseMediaType(contentType)
		if err != nil {
			t.Fatal(err)
		}
		form, err := multipart.NewReader(body, params["boundary"]).ReadForm(1024)
		if err != nil {
			t.Fatal(err)
		}
		files := form.File["file"]
		if len(files) != 1 {
			t.Fatalf("%s file parts = %d, want 1", test.name, len(files))
		}
		if got := files[0].Header.Get("Content-Type"); got != test.want {
			t.Fatalf("%s file part Content-Type = %q, want %q", test.name, got, test.want)
		}
	}
}

func TestUploadDoesNotLowLevelRetryStreamingBody(t *testing.T) {
	var uploadRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sapi/upload" || r.URL.Query().Get("action") != "save" {
			http.NotFound(w, r)
			return
		}
		uploadRequests++
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Fatal(err)
		}
		http.Error(w, "temporary failure", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx := context.Background()
	f := &Fs{
		name:   "o2test",
		opt:    testOAuthOptions(server.URL),
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.dirCache = dircache.New("", "1", f)

	src := object.NewStaticObjectInfo("upload.txt", time.Now(), int64(len("payload")), true, nil, f)
	_, err := f.upload(ctx, strings.NewReader("payload"), src)
	if err == nil {
		t.Fatal("expected upload error")
	}
	if !fserrors.IsRetryError(err) {
		t.Fatalf("expected retryable upload error, got %T: %v", err, err)
	}
	if uploadRequests != 1 {
		t.Fatalf("upload requests = %d, want 1", uploadRequests)
	}
}
