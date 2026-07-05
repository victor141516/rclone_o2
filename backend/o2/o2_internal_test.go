package o2

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	plc := "persistent-login-cookie"

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
	if got := revealIfObscured(obscure.MustObscure(plc)); got != plc {
		t.Fatalf("obscured PLC revealed as %q", got)
	}
}

func TestNormalizeDeviceID(t *testing.T) {
	for _, test := range []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "web-test-device", want: "web-test-device"},
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
		{in: "636025908", want: "34636025908"},
		{in: "+34 636 025 908", want: "34636025908"},
		{in: "0034-636-025-908", want: "34636025908"},
	} {
		if got := normalizePhoneNumber(test.in); got != test.want {
			t.Fatalf("normalizePhoneNumber(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestSessionNode(t *testing.T) {
	if got := sessionNode("ABC.1i221"); got != "1i221" {
		t.Fatalf("sessionNode = %q, want 1i221", got)
	}
	if got := sessionNode("ABC"); got != "" {
		t.Fatalf("sessionNode without suffix = %q, want empty", got)
	}
	if got := sessionNode("ABC."); got != "" {
		t.Fatalf("sessionNode with empty suffix = %q, want empty", got)
	}
}

func TestAuthFormBodyPreservesBrowserOrder(t *testing.T) {
	got := formBody(
		"csrfmiddlewaretoken", "csrf-token",
		"corr", "corr-1",
		"nonce", "nonce-1",
		"trans", "trans-1",
		"code", "1234",
		"action", "finish",
	)
	want := "csrfmiddlewaretoken=csrf-token&corr=corr-1&nonce=nonce-1&trans=trans-1&code=1234&action=finish"
	if got != want {
		t.Fatalf("formBody = %q, want %q", got, want)
	}
}

func TestUploadMetadataUsesBrowserShapeForAllTypes(t *testing.T) {
	for _, name := range []string{"song.m4a", "note.txt", "program.exe", "random.unknownext"} {
		got, err := uploadMetadata(name, 42, 123)
		if err != nil {
			t.Fatal(err)
		}

		var payload map[string]map[string]any
		if err := json.Unmarshal(got, &payload); err != nil {
			t.Fatal(err)
		}
		data := payload["data"]
		if data["name"] != name {
			t.Fatalf("name = %q, want %q", data["name"], name)
		}
		if data["modificationdate"] != "" {
			t.Fatalf("modificationdate = %q", data["modificationdate"])
		}
		if _, ok := data["contenttype"]; ok {
			t.Fatalf("%s metadata should not include contenttype", name)
		}
	}
}

func TestBackendConfigAllSMSLoginCompletes(t *testing.T) {
	ri, err := fs.Find("o2")
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sapi/login/mobileconnect" && r.URL.Query().Get("action") == "start":
			if got := r.Header.Get("X-deviceid"); !strings.HasPrefix(got, "web-") {
				t.Fatalf("start X-deviceid = %q, want web-*", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("msisdn"); got != "34636025908" {
				t.Fatalf("msisdn = %q, want normalized phone", got)
			}
			if got := r.Form.Get("rememberme"); got != "true" {
				t.Fatalf("rememberme = %q, want true", got)
			}
			_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{AuthorizationURL: server.URL + "/es/oauth2/authorize?state=state-1"}})

		case r.URL.Path == "/es/oauth2/authorize":
			http.SetCookie(w, &http.Cookie{Name: "connect.sid", Value: "connect-cookie", Path: "/"})
			http.Redirect(w, r, "/es/sba/authenticate?jwt=test", http.StatusFound)

		case r.URL.Path == "/es/sba/authenticate":
			http.SetCookie(w, &http.Cookie{Name: "xbacsrftoken", Value: "csrf-cookie", Path: "/"})
			_, _ = w.Write([]byte(`<html><form action="/es/sba/finish" method="post">
				<input type="hidden" name="csrfmiddlewaretoken" value="csrf-token">
				<input type="hidden" name="corr" value="corr-1">
				<input type="hidden" name="nonce" value="nonce-1">
				<input type="hidden" name="trans" value="trans-1">
				<input type="hidden" name="code" value="">
			</form></html>`))

		case r.URL.Path == "/es/sba/finish":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("code"); got != "1234" {
				t.Fatalf("SMS code = %q, want 1234", got)
			}
			if got := r.Header.Get("X-CSRFToken"); got != "csrf-token" {
				t.Fatalf("X-CSRFToken = %q, want csrf-token", got)
			}
			http.Redirect(w, r, "/es/authrouter/authenticated?jwt=authenticated", http.StatusFound)

		case r.URL.Path == "/es/authrouter/authenticated":
			if got, err := r.Cookie("connect.sid"); err != nil || got.Value != "connect-cookie" {
				t.Fatalf("authenticated connect.sid cookie = %v, %v; want connect-cookie", got, err)
			}
			http.Redirect(w, r, "/es/oauth2/authorize/confirm?jwt=confirm", http.StatusFound)

		case r.URL.Path == "/es/oauth2/authorize/confirm":
			if got, err := r.Cookie("connect.sid"); err != nil || got.Value != "connect-cookie" {
				t.Fatalf("confirm connect.sid cookie = %v, %v; want connect-cookie", got, err)
			}
			http.Redirect(w, r, "/ui/html/mobileconnect.html?code=auth-code&state=callback-state", http.StatusFound)

		case r.URL.Path == "/ui/html/mobileconnect.html":
			_, _ = w.Write([]byte("ok"))

		case r.URL.Path == "/sapi/login/mobileconnect" && r.URL.Query().Get("action") == "login":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("keytype"); got != "authorizationcode" {
				t.Fatalf("keytype = %q, want authorizationcode", got)
			}
			if got := r.Form.Get("state"); got != "callback-state" {
				t.Fatalf("state = %q, want callback-state", got)
			}
			if got := r.Form.Get("key"); got != "auth-code" {
				t.Fatalf("key = %q, want auth-code", got)
			}
			http.SetCookie(w, &http.Cookie{Name: "validationKey", Value: "validation-new", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "session-new", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "PLC", Value: "plc-new", Path: "/"})
			_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{ValidationKey: "validation-new"}})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	m := configmap.Simple{"type": "o2", "api_url": server.URL, "upload_url": server.URL}
	choices := configmap.Simple{
		"phone_number":       "636 025 908",
		"config_sms_code":    "1234",
		"config_fs_advanced": "false",
	}
	out, err := fs.BackendConfig(context.Background(), "o2test", m, ri, choices, fs.ConfigIn{State: fs.ConfigAll})
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Fatalf("out = %#v", out)
	}
	if got := m["phone_number"]; got != "34636025908" {
		t.Fatalf("phone_number = %q, want normalized phone", got)
	}
	if got := revealIfObscured(m["validation_key"]); got != "validation-new" {
		t.Fatalf("validation_key = %q, want validation-new", got)
	}
	if got := revealIfObscured(m["jsessionid"]); got != "session-new" {
		t.Fatalf("jsessionid = %q, want session-new", got)
	}
	if got := revealIfObscured(m["plc"]); got != "plc-new" {
		t.Fatalf("plc = %q, want plc-new", got)
	}
	if got := m["device_id"]; !strings.HasPrefix(got, "web-") {
		t.Fatalf("device_id = %q, want web-*", got)
	}
}

func TestAPIRenewsExpiredSessionAndSavesIt(t *testing.T) {
	ctx := context.Background()
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sapi/media/folder/root" || r.URL.Query().Get("action") != "get" {
			http.NotFound(w, r)
			return
		}
		requests++
		switch requests {
		case 1:
			if got := r.URL.Query().Get("validationkey"); got != "validation-old" {
				t.Fatalf("first validationkey = %q, want validation-old", got)
			}
			if got, err := r.Cookie("validationKey"); err != nil || got.Value != "validation-old" {
				t.Fatalf("first validationKey cookie = %v, %v; want validation-old", got, err)
			}
			if got, err := r.Cookie("PLC"); err != nil || got.Value != "plc-old" {
				t.Fatalf("first PLC cookie = %v, %v; want plc-old", got, err)
			}
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "session-new", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "PLC", Value: "plc-new", Path: "/"})
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(api.Envelope{Error: &api.Error{
				Code:    "SEC-1003",
				Message: "expired",
				Data:    "validation-new",
			}})
		case 2:
			if got := r.URL.Query().Get("validationkey"); got != "validation-new" {
				t.Fatalf("second validationkey = %q, want validation-new", got)
			}
			for name, want := range map[string]string{
				"validationKey": "validation-new",
				"JSESSIONID":    "session-new",
				"PLC":           "plc-new",
			} {
				got, err := r.Cookie(name)
				if err != nil || got.Value != want {
					t.Fatalf("second %s cookie = %v, %v; want %s", name, got, err, want)
				}
			}
			_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Folders: []api.Folder{{Name: "/", ID: 42}}}})
		case 3:
			if got := r.URL.Query().Get("validationkey"); got != "validation-new" {
				t.Fatalf("third validationkey = %q, want validation-new", got)
			}
			for name, want := range map[string]string{
				"validationKey": "validation-new",
				"JSESSIONID":    "session-new",
				"PLC":           "plc-new",
			} {
				got, err := r.Cookie(name)
				if err != nil || got.Value != want {
					t.Fatalf("third %s cookie = %v, %v; want %s", name, got, err, want)
				}
			}
			_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Folders: []api.Folder{{Name: "/", ID: 43}}}})
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()

	m := configmap.Simple{"phone_number": "34636025908", "api_url": server.URL, "upload_url": server.URL}
	f := &Fs{
		name: "o2test",
		opt: Options{
			ValidationKey: "validation-old",
			PLC:           "plc-old",
			DeviceID:      "web-test-device",
			APIURL:        server.URL,
			UploadURL:     server.URL,
			Enc:           encoder.Display | encoder.EncodeInvalidUtf8,
		},
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
	if got := revealIfObscured(m["plc"]); got != "plc-new" {
		t.Fatalf("saved plc = %q, want plc-new", got)
	}
	if got := m["device_id"]; got != "web-test-device" {
		t.Fatalf("saved device_id = %q, want web-test-device", got)
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

func TestUploadRefreshesSessionWhenConfiguredAndSendsKnownLengthMultipartBody(t *testing.T) {
	const payload = "payload"

	var renewalRequests int
	var uploadRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sapi/media/folder/root" && r.URL.Query().Get("action") == "get" {
			renewalRequests++
			switch renewalRequests {
			case 1:
				if _, err := r.Cookie("JSESSIONID"); err == nil {
					t.Fatal("renewal request should omit JSESSIONID")
				}
				if got, err := r.Cookie("validationKey"); err != nil || got.Value != "24553931775f412a57804d272b305848" {
					t.Fatalf("renewal validationKey cookie = %v, %v", got, err)
				}
				if got, err := r.Cookie("PLC"); err != nil || got.Value != "persistent-login-cookie" {
					t.Fatalf("renewal PLC cookie = %v, %v", got, err)
				}
				http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "renewed-session", Path: "/"})
				http.SetCookie(w, &http.Cookie{Name: "PLC", Value: "renewed-plc", Path: "/"})
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(api.Envelope{Error: &api.Error{
					Code:    "SEC-1003",
					Message: "expired",
					Data:    "renewed-validation",
				}})
			case 2:
				for name, want := range map[string]string{
					"validationKey": "renewed-validation",
					"JSESSIONID":    "renewed-session",
					"PLC":           "renewed-plc",
				} {
					got, err := r.Cookie(name)
					if err != nil || got.Value != want {
						t.Fatalf("verified %s cookie = %v, %v; want %s", name, got, err, want)
					}
				}
				_ = json.NewEncoder(w).Encode(api.Envelope{Data: api.Data{Folders: []api.Folder{{Name: "/", ID: 1}}}})
			default:
				t.Fatalf("unexpected renewal request %d", renewalRequests)
			}
			return
		}
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
		if len(cookies) != 1 || cookies[0].Name != "JSESSIONID" || cookies[0].Value != "renewed-session" {
			t.Fatalf("upload cookies = %#v, want renewed JSESSIONID only", cookies)
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
		name: "o2test",
		opt: Options{
			ValidationKey:        "24553931775f412a57804d272b305848",
			JSessionID:           "2D4F6F492842ADB18DEB929ACE9984E8.1i221",
			PLC:                  "persistent-login-cookie",
			DeviceID:             "web-test-device",
			APIURL:               server.URL,
			UploadURL:            server.URL,
			RefreshUploadSession: true,
			Enc:                  encoder.Display | encoder.EncodeInvalidUtf8,
		},
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
	if renewalRequests != 2 {
		t.Fatalf("renewal requests = %d, want 2", renewalRequests)
	}
}

func TestUploadDoesNotRefreshSessionByDefault(t *testing.T) {
	const payload = "payload"

	var renewalRequests int
	var uploadRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sapi/media/folder/root" && r.URL.Query().Get("action") == "get" {
			renewalRequests++
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/sapi/upload" || r.URL.Query().Get("action") != "save" {
			t.Fatalf("unexpected request %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		uploadRequests++
		cookies := r.Cookies()
		if len(cookies) != 1 || cookies[0].Name != "JSESSIONID" || cookies[0].Value != "2D4F6F492842ADB18DEB929ACE9984E8.1i221" {
			t.Fatalf("upload cookies = %#v, want original JSESSIONID only", cookies)
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(api.UploadResponse{Success: "true", ID: "123", Status: "V", ETag: "etag-1"})
	}))
	defer server.Close()

	ctx := context.Background()
	f := &Fs{
		name: "o2test",
		opt: Options{
			ValidationKey: "24553931775f412a57804d272b305848",
			JSessionID:    "2D4F6F492842ADB18DEB929ACE9984E8.1i221",
			PLC:           "persistent-login-cookie",
			DeviceID:      "web-test-device",
			APIURL:        server.URL,
			UploadURL:     server.URL,
			Enc:           encoder.Display | encoder.EncodeInvalidUtf8,
		},
		client: server.Client(),
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.dirCache = dircache.New("", "1", f)

	src := object.NewStaticObjectInfo("upload.txt", time.Now(), int64(len(payload)), true, nil, f)
	if _, err := f.upload(ctx, strings.NewReader(payload), src); err != nil {
		t.Fatal(err)
	}
	if uploadRequests != 1 {
		t.Fatalf("upload requests = %d, want 1", uploadRequests)
	}
	if renewalRequests != 0 {
		t.Fatalf("renewal requests = %d, want 0", renewalRequests)
	}
}

func TestUploadRequestAlwaysUsesAsync(t *testing.T) {
	ctx := context.Background()
	f := &Fs{
		opt: Options{
			ValidationKey: "validation",
			DeviceID:      "web-test-device",
			APIURL:        "https://cloud.o2online.es",
			UploadURL:     "https://upload.cloud.o2online.es",
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
