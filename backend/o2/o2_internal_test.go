package o2

import (
	"context"
	"encoding/json"
	"io"
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
		{in: "test-device", want: "web-test-device"},
		{in: " test-device ", want: "web-test-device"},
	} {
		if got := normalizeDeviceID(test.in); got != test.want {
			t.Fatalf("normalizeDeviceID(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestBackendConfigAllBrowserSessionCompletes(t *testing.T) {
	ri, err := fs.Find("o2")
	if err != nil {
		t.Fatal(err)
	}

	m := configmap.Simple{"type": "o2"}
	choices := configmap.Simple{
		"validation_key":     "24553931775f412a57804d272b305848",
		"jsessionid":         "2D4F6F492842ADB18DEB929ACE9984E8.1i221",
		"device_id":          "web-test-device",
		"config_fs_advanced": "false",
	}
	out, err := fs.BackendConfig(context.Background(), "o2test", m, ri, choices, fs.ConfigIn{State: fs.ConfigAll})
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Fatalf("out = %#v", out)
	}
	for key, want := range choices {
		if key == "config_fs_advanced" {
			continue
		}
		if got := m[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
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
		rootID: "1",
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
