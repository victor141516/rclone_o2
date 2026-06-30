package o2

import (
	"bytes"
	"context"
	"encoding/json"
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

type apiError struct {
	StatusCode int
	Code       string
	Message    string
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
	req.Header.Set("X-deviceid", f.opt.DeviceID)
	req.Header.Set("Referer", f.opt.APIURL+"/")
	req.Header.Set("Origin", f.opt.APIURL)
	req.AddCookie(&http.Cookie{Name: "validationKey", Value: f.opt.ValidationKey})
	req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: f.opt.JSessionID})
}

func (f *Fs) addValidationKey(rawURL string) (string, error) {
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
	u, err := f.addValidationKey(rawURL)
	if err != nil {
		return err
	}

	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		req, err := f.newAPIRequest(ctx, method, u, body)
		if err != nil {
			return false, err
		}

		fs.Debugf(f, "O2 API %s %s", method, redactedURL(u))
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

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseAPIError(resp)
	}
	return decodeAPIResponse(resp, out)
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
	return &apiError{StatusCode: statusCode, Code: e.Code, Message: e.Message}
}

func parseAPIError(resp *http.Response) error {
	var env api.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err == nil && env.Error != nil {
		return &apiError{StatusCode: resp.StatusCode, Code: env.Error.Code, Message: env.Error.Message}
	}
	return &apiError{StatusCode: resp.StatusCode}
}

func redactedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for _, key := range []string{"validationkey", "k", "token", "key", "state", "nonce"} {
		if q.Get(key) != "" {
			q.Set(key, "REDACTED")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func closeResponse(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}
