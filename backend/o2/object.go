package o2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/rclone/rclone/backend/o2/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/hash"
)

// SetModTime sets the modification time.
func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorNotImplemented
}

// Open opens a remote object for reading.
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	fs.FixRangeOption(options, o.size)

	media, err := o.fs.getMedia(ctx, o.id)
	if err != nil {
		return nil, err
	}
	downloadURL, err := o.downloadURL(media)
	if err != nil {
		return nil, err
	}

	var resp *http.Response
	err = o.fs.pacer.Call(func() (bool, error) {
		req, err := o.downloadRequest(ctx, downloadURL, options)
		if err != nil {
			return false, err
		}

		fs.Debugf(o, "Downloading O2 object id=%s remote=%q", o.id, o.remote)
		resp, err = o.fs.client.Do(req)
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		closeResponse(resp)
		return nil, &apiError{StatusCode: resp.StatusCode}
	}
	return resp.Body, nil
}

// Update updates an object.
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	newObject, err := o.fs.upload(ctx, in, src, options...)
	if err != nil {
		return err
	}
	if err := o.Remove(ctx); err != nil {
		fs.Debugf(o, "Failed to delete old O2 object id=%s after update: %v", o.id, err)
	}
	no := newObject.(*Object)
	*o = *no
	return nil
}

// Remove removes an object.
func (o *Object) Remove(ctx context.Context) error {
	return o.fs.deleteFile(ctx, o.id)
}

// Fs returns the parent Fs.
func (o *Object) Fs() fs.Info { return o.fs }

// String returns object as string.
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path.
func (o *Object) Remote() string { return o.remote }

// ModTime returns the modification time.
func (o *Object) ModTime(ctx context.Context) time.Time { return o.modTime }

// Size returns the object size.
func (o *Object) Size() int64 { return o.size }

// Hash returns an unsupported hash.
func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Storable says this object can be stored.
func (o *Object) Storable() bool { return true }

// MimeType returns the content type.
func (o *Object) MimeType(ctx context.Context) string {
	if o.mimeType != "" {
		return o.mimeType
	}
	return fs.MimeTypeFromName(o.remote)
}

func (f *Fs) newObjectFromMedia(remote string, item api.Media) *Object {
	mtime := msToTime(item.ModificationDate)
	if mtime.IsZero() {
		mtime = msToTime(item.Date)
	}
	return &Object{
		fs:       f,
		remote:   remote,
		id:       item.ID,
		size:     item.Size,
		modTime:  mtime,
		mimeType: fs.MimeTypeFromName(remote),
	}
}

func (o *Object) downloadURL(media api.Media) (string, error) {
	if media.URL == "" {
		return "", errors.New("download URL missing from O2 metadata")
	}

	u, err := url.Parse(media.URL)
	if err != nil {
		return media.URL, nil
	}
	q := u.Query()
	if q.Get("filename") == "" {
		q.Set("filename", path.Base(o.remote))
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

func (o *Object) downloadRequest(ctx context.Context, downloadURL string, options []fs.OpenOption) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, err
	}
	for _, option := range options {
		key, value := option.Header()
		if key != "" {
			req.Header.Set(key, value)
			continue
		}
		if option.Mandatory() {
			fs.Debugf(o, "Unsupported mandatory open option %T", option)
			return nil, fmt.Errorf("unsupported mandatory open option: %T", option)
		}
	}
	o.fs.addHeaders(req)
	return req, nil
}

func msToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.Unix(0, ms*int64(time.Millisecond))
}
