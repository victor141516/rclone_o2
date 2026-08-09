package o2

import (
	"fmt"
	"strings"
)

const (
	providerO2       = "o2"
	providerMovistar = "movistar"

	defaultMovistarAPIURL    = "https://micloud.movistar.es"
	defaultMovistarUploadURL = "https://micloud.movistar.es"

	defaultMovistarOAuthAuthorizeURL = "https://apiseg.telefonica.es/openid/connect/cus/col/auth/oauth/v2/authorize"
	defaultMovistarOAuthTokenURL     = "https://apiseg.telefonica.es/openid/connect/cus/col/auth/oauth/v2/token"
	defaultMovistarOAuthRedirectURL  = "https://micloud.movistar.es/ui/html/clientoauth.html"
	defaultMovistarOAuthClientID     = "b99e5095-7a36-42c1-83b6-6f05d0f13ea1"
	defaultMovistarOAuthClientSecret = "e22fdd6b-636a-4bfc-bb4a-aa8ed6d131d8"

	o2OAuthPlatform       = "android"
	movistarOAuthPlatform = "macos"
	o2APIUserAgent        = "omh android client 4.0.1"
	movistarAPIUserAgent  = "omh macos client 32.0.7.1 (32.0.7)"
	o2BrowserUserAgent    = "Mozilla/5.0 (Linux; Android 15; Pixel 9 Build/AP4A.250205.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/137.0.7151.115 Mobile Safari/537.36"
	movistarBrowserUA     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7_2) AppleWebKit/537.36 (KHTML, like Gecko) QtWebEngine/5.15.2 Chrome/83.0.4103.122 Safari/537.36"

	t3O2ManageCredentialPath       = "/cus/segu/v5/seguCredentialO2s/manageCredentialMobileO2"
	t3O2VerifyCredentialPath       = "/cus/segu/v5/seguCredentialO2s/verifyCredentialMobileO2"
	t3MovistarManageCredentialPath = "/cus/segu/v6/loginCredentialLAs/manageCredentialMobile"
	t3MovistarVerifyCredentialPath = "/cus/segu/v6/loginCredentialLAs/verifyCredentialMobile"
)

var (
	movistarOAuthAuthorizeURL = defaultMovistarOAuthAuthorizeURL
	movistarOAuthTokenURL     = defaultMovistarOAuthTokenURL
	movistarOAuthRedirectURL  = defaultMovistarOAuthRedirectURL
	movistarOAuthClientID     = defaultMovistarOAuthClientID
	movistarOAuthClientSecret = defaultMovistarOAuthClientSecret
)

type authFlow int

const (
	authFlowO2SMS authFlow = iota
	authFlowBrowserPKCE
)

type providerProfile struct {
	Name              string
	Description       string
	APIURL            string
	UploadURL         string
	OAuthAuthorizeURL string
	OAuthTokenURL     string
	OAuthRedirectURL  string
	OAuthClientID     string
	OAuthClientSecret string
	OAuthScope        string
	OAuthAccessType   string
	OAuthPlatform     string
	APIUserAgent      string
	BrowserUserAgent  string
	XRequestedWith    string
	DevicePrefix      string
	AuthFlow          authFlow
	RequirePhone      bool
	RequireOAuthToken bool
	RequireSession    bool
	ErrorPrefix       string
	ConsumerParam     string
	ManagePath        string
	VerifyPath        string
	ManageMobileKey   string
	ManageSessionKey  string
	VerifySessionKey  string
}

func normalizeProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", providerO2:
		return providerO2
	case providerMovistar, "movistar-cloud", "movistar_cloud":
		return providerMovistar
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func (opt Options) provider() (providerProfile, error) {
	switch normalizeProvider(opt.Provider) {
	case providerO2:
		clientID, clientSecret, err := oauthClientCredentials()
		if err != nil {
			return providerProfile{}, err
		}
		return providerProfile{
			Name:              providerO2,
			Description:       "O2 Cloud",
			APIURL:            defaultAPIURL,
			UploadURL:         defaultUploadURL,
			OAuthAuthorizeURL: oauthAuthorizeURL,
			OAuthTokenURL:     oauthTokenURL,
			OAuthRedirectURL:  oauthRedirectURL,
			OAuthClientID:     clientID,
			OAuthClientSecret: clientSecret,
			OAuthScope:        "openid",
			OAuthAccessType:   "offline",
			OAuthPlatform:     o2OAuthPlatform,
			APIUserAgent:      o2APIUserAgent,
			BrowserUserAgent:  o2BrowserUserAgent,
			XRequestedWith:    "es.o2online.cloud",
			DevicePrefix:      "fac-",
			AuthFlow:          authFlowO2SMS,
			RequirePhone:      true,
			RequireOAuthToken: true,
			RequireSession:    true,
			ErrorPrefix:       "O2",
			ConsumerParam:     "client_name",
			ManagePath:        t3O2ManageCredentialPath,
			VerifyPath:        t3O2VerifyCredentialPath,
			ManageMobileKey:   "mobile",
			ManageSessionKey:  "sessionID",
			VerifySessionKey:  "sessionID",
		}, nil
	case providerMovistar:
		return providerProfile{
			Name:              providerMovistar,
			Description:       "Movistar Cloud",
			APIURL:            defaultMovistarAPIURL,
			UploadURL:         defaultMovistarUploadURL,
			OAuthAuthorizeURL: movistarOAuthAuthorizeURL,
			OAuthTokenURL:     movistarOAuthTokenURL,
			OAuthRedirectURL:  movistarOAuthRedirectURL,
			OAuthClientID:     movistarOAuthClientID,
			OAuthClientSecret: movistarOAuthClientSecret,
			OAuthScope:        "openid",
			OAuthAccessType:   "offline",
			OAuthPlatform:     movistarOAuthPlatform,
			APIUserAgent:      movistarAPIUserAgent,
			BrowserUserAgent:  movistarBrowserUA,
			DevicePrefix:      "mox-",
			AuthFlow:          authFlowO2SMS,
			RequirePhone:      true,
			RequireOAuthToken: true,
			RequireSession:    true,
			ErrorPrefix:       "Movistar",
			ConsumerParam:     "consumer_id",
			ManagePath:        t3MovistarManageCredentialPath,
			VerifyPath:        t3MovistarVerifyCredentialPath,
			ManageMobileKey:   "Mobile",
			ManageSessionKey:  "sessionId",
			VerifySessionKey:  "sessionID",
		}, nil
	default:
		return providerProfile{}, fmt.Errorf("unknown O2 backend provider %q", opt.Provider)
	}
}

func providerDefaults(provider string) (apiURL, uploadURL string) {
	switch normalizeProvider(provider) {
	case providerMovistar:
		return defaultMovistarAPIURL, defaultMovistarUploadURL
	default:
		return defaultAPIURL, defaultUploadURL
	}
}
