package o2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rclone/rclone/backend/o2/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/fserrors"
)

var retryErrorCodes = []int{
	http.StatusTooManyRequests,
	http.StatusInternalServerError,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
}

var redactedURLParameters = []string{
	"validationkey", "k", "token", "key", "state", "nonce", "code", "sessionID", "sessionId", "sessionData", "jwt", "otp",
}

type apiError struct {
	StatusCode int
	Code       string
	Message    string
	Data       string
}

type apiErrorEnvelope struct {
	Error *api.Error `json:"error"`
}

func (e *apiError) Error() string {
	if e.Code != "" || e.Message != "" {
		return fmt.Sprintf("o2 api error: status %d code %q: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("o2 api error: status %d", e.StatusCode)
}

func shouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	return fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(resp, retryErrorCodes), err
}

func (f *Fs) addHeaders(req *http.Request) {
	f.addCommonHeaders(req)
	f.addSessionCookies(req)
}

func (f *Fs) addCommonHeaders(req *http.Request) {
	f.addBaseHeaders(req)
	authorization, err := f.oauthAuthorization()
	if err == nil {
		req.Header.Set("Authorization", authorization)
	}
}

func (f *Fs) addBaseHeaders(req *http.Request) {
	profile, err := f.opt.provider()
	if err != nil {
		profile, _ = (Options{}).provider()
	}
	addProfileHeaders(req, profile)
	req.Header.Set("User-Agent", profile.APIUserAgent)
	req.Header.Set("X-deviceid", f.opt.DeviceID)
	req.Header.Set("Referer", f.opt.APIURL+"/")
	req.Header.Set("Origin", f.opt.APIURL)
}

func addBrowserHeaders(req *http.Request) {
	profile, err := (Options{}).provider()
	if err != nil {
		for key, value := range browserHeaders {
			req.Header.Set(key, value)
		}
		return
	}
	addProfileHeaders(req, profile)
}

func addProfileHeaders(req *http.Request, profile providerProfile) {
	for key, value := range profileBrowserHeaders(profile) {
		req.Header.Set(key, value)
	}
}

func addFetchHeaders(req *http.Request, site string) {
	req.Header.Set("Priority", "u=1, i")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", site)
}

func (f *Fs) addSessionCookies(req *http.Request) {
	f.authMu.Lock()
	defer f.authMu.Unlock()
	addCookies(req, "JSESSIONID", f.opt.JSessionID)
}

func (f *Fs) addUploadCookie(req *http.Request) {
	f.authMu.Lock()
	defer f.authMu.Unlock()
	addCookies(req, "JSESSIONID", f.opt.JSessionID)
}

func addCookies(req *http.Request, pairs ...string) {
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			req.AddCookie(&http.Cookie{Name: pairs[i], Value: pairs[i+1]})
		}
	}
}

func (f *Fs) addValidationKey(rawURL string) (string, error) {
	f.authMu.Lock()
	defer f.authMu.Unlock()
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if q.Get("validationkey") == "" {
		q.Set("validationkey", f.opt.ValidationKey)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

type requestBody func() (body io.Reader, contentType string, err error)

func (f *Fs) doJSON(ctx context.Context, method, rawURL string, in, out any) error {
	body, err := jsonRequestBody(in)
	if err != nil {
		return err
	}
	return f.doRequest(ctx, method, rawURL, body, out)
}

func (f *Fs) doForm(ctx context.Context, method, rawURL string, form url.Values, out any) error {
	return f.doRequest(ctx, method, rawURL, formRequestBody(form), out)
}

func jsonRequestBody(in any) (requestBody, error) {
	if in == nil {
		return noRequestBody, nil
	}

	data, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	return func() (io.Reader, string, error) {
		return bytes.NewReader(data), "application/json;charset=UTF-8", nil
	}, nil
}

func formRequestBody(form url.Values) requestBody {
	data := form.Encode()
	return func() (io.Reader, string, error) {
		return strings.NewReader(data), "application/x-www-form-urlencoded; charset=UTF-8", nil
	}
}

func noRequestBody() (io.Reader, string, error) {
	return nil, "", nil
}

func (f *Fs) doRequest(ctx context.Context, method, rawURL string, body requestBody, out any) (err error) {
	for try := 0; try < 2; try++ {
		u, err := f.addValidationKey(rawURL)
		if err != nil {
			return err
		}

		resp, err := f.doHTTPRequest(ctx, method, u, body)
		if err != nil {
			return err
		}

		if !successful(resp) {
			err := parseAPIError(resp)
			closeResponse(resp)
			if try == 0 {
				if isAPIStatus(err, http.StatusUnauthorized) && f.hasOAuthCredentials() {
					if err := f.reloginOAuth(ctx); err != nil {
						if isAPIStatus(err, http.StatusUnauthorized) {
							return fmt.Errorf("O2 OAuth refresh token was rejected; run \"rclone config reconnect %s:\" to authenticate by SMS again", f.name)
						}
						return fmt.Errorf("failed to renew O2 OAuth session: %w", err)
					}
					continue
				}
			}
			if isAPIStatus(err, http.StatusUnauthorized) {
				return fmt.Errorf("O2 OAuth session could not be renewed; run \"rclone config reconnect %s:\" to authenticate by SMS again", f.name)
			}
			return err
		}

		if err := f.captureOAuthAuthorization(resp.Header.Get("Authorization")); err != nil {
			closeResponse(resp)
			return err
		}
		defer fs.CheckClose(resp.Body, &err)
		return decodeAPIResponse(resp, out)
	}

	return errors.New("O2 session renewal failed")
}

func (f *Fs) doHTTPRequest(ctx context.Context, method, rawURL string, body requestBody) (resp *http.Response, err error) {
	err = f.pacer.Call(func() (bool, error) {
		req, err := f.newAPIRequest(ctx, method, rawURL, body)
		if err != nil {
			return false, err
		}

		fs.Debugf(f, "O2 API %s %s", method, redactedURL(rawURL))
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
		return nil, err
	}
	return resp, nil
}

func (f *Fs) newAPIRequest(ctx context.Context, method, rawURL string, body requestBody) (*http.Request, error) {
	reader, contentType, err := body()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, err
	}
	f.addHeaders(req)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "*/*")
	addFetchHeaders(req, "same-origin")
	return req, nil
}

func decodeAPIResponse(resp *http.Response, out any) error {
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return err
	}
	return responseError(resp.StatusCode, out)
}

func responseError(statusCode int, out any) error {
	switch e := out.(type) {
	case *api.Envelope:
		return envelopeError(statusCode, e.Error)
	case *apiErrorEnvelope:
		return envelopeError(statusCode, e.Error)
	case *api.UploadResponse:
		return envelopeError(statusCode, e.Error)
	default:
		return nil
	}
}

func envelopeError(statusCode int, e *api.Error) error {
	if e == nil {
		return nil
	}
	return &apiError{StatusCode: statusCode, Code: e.Code, Message: e.Message, Data: e.Data}
}

func parseAPIError(resp *http.Response) error {
	var env api.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err == nil && env.Error != nil {
		return &apiError{StatusCode: resp.StatusCode, Code: env.Error.Code, Message: env.Error.Message, Data: env.Error.Data}
	}
	return &apiError{StatusCode: resp.StatusCode}
}

func isAPIStatus(err error, statusCode int) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.StatusCode == statusCode
}

func redactedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for _, key := range redactedURLParameters {
		if q.Get(key) != "" {
			q.Set(key, "REDACTED")
		}
	}
	u.RawQuery = q.Encode()
	if _, fragmentQuery, found := strings.Cut(u.Fragment, "?"); found {
		fragmentValues, err := url.ParseQuery(fragmentQuery)
		if err == nil {
			for _, key := range redactedURLParameters {
				if fragmentValues.Get(key) != "" {
					fragmentValues.Set(key, "REDACTED")
				}
			}
			u.Fragment = strings.SplitN(u.Fragment, "?", 2)[0] + "?" + fragmentValues.Encode()
		}
	}
	return u.String()
}

func closeResponse(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

func successful(resp *http.Response) bool {
	return resp.StatusCode >= 200 && resp.StatusCode <= 299
}
