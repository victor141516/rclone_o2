// Package o2 provides an interface to O2 Cloud.
package o2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
)

const (
	defaultAPIURL    = "https://cloud.o2online.es"
	defaultUploadURL = "https://upload.cloud.o2online.es"
	rootID           = "0"

	minSleep      = 10 * time.Millisecond
	maxSleep      = 2 * time.Second
	decayConstant = 2
)

func init() {
	fs.Register(&fs.RegInfo{
		Name:        "o2",
		Description: "O2 Cloud",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:       "validation_key",
			Help:       "O2 Cloud validationKey cookie from a logged-in browser session.\n\nLog in at https://cloud.o2online.es/ in your browser, open the developer tools for cloud.o2online.es, and copy the cookie named validationKey.",
			Sensitive:  true,
			IsPassword: true,
			Required:   true,
		}, {
			Name:       "jsessionid",
			Help:       "O2 Cloud JSESSIONID cookie from the same logged-in browser session.\n\nIn browser developer tools, inspect cookies for https://cloud.o2online.es/ and copy the cookie named JSESSIONID.",
			Sensitive:  true,
			IsPassword: true,
			Required:   true,
		}, {
			Name:     "device_id",
			Help:     "O2 Cloud web device id from the same logged-in browser session.\n\nIn browser developer tools, check local storage for cloud.o2online.es and copy the value of omhls.fingerprintKey. If the value does not start with web-, rclone will add that prefix.",
			Required: true,
		}, {
			Name:     "root_folder_id",
			Help:     "Numeric root folder id. Leave blank to discover it from the API.",
			Advanced: true,
		}, {
			Name:     "api_url",
			Help:     "O2 Cloud API URL.",
			Default:  defaultAPIURL,
			Advanced: true,
		}, {
			Name:     "upload_url",
			Help:     "O2 Cloud upload API URL.",
			Default:  defaultUploadURL,
			Advanced: true,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			Default:  encoder.Display | encoder.EncodeInvalidUtf8,
		}},
	})
}

// Options defines the configuration for this backend.
type Options struct {
	ValidationKey string               `config:"validation_key"`
	JSessionID    string               `config:"jsessionid"`
	DeviceID      string               `config:"device_id"`
	RootFolderID  string               `config:"root_folder_id"`
	APIURL        string               `config:"api_url"`
	UploadURL     string               `config:"upload_url"`
	Enc           encoder.MultiEncoder `config:"encoding"`
}

// Fs represents an O2 Cloud remote.
type Fs struct {
	name     string
	root     string
	opt      Options
	features *fs.Features
	client   *http.Client
	pacer    *fs.Pacer
	dirCache *dircache.DirCache
	rootID   string
}

// Object describes an O2 Cloud object.
type Object struct {
	fs       *Fs
	remote   string
	id       string
	folderID int64
	size     int64
	modTime  time.Time
	mimeType string
	etag     string
	url      string
}

// NewFs constructs an Fs from the path.
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt, err := readOptions(m)
	if err != nil {
		return nil, err
	}

	f := &Fs{
		name:   name,
		root:   parsePath(root),
		opt:    opt,
		client: newHTTPClient(ctx),
		pacer:  newPacer(ctx),
	}
	f.fillFeatures(ctx)

	rootFolderID, err := f.configuredRootID(ctx)
	if err != nil {
		return nil, err
	}
	f.rootID = rootFolderID
	f.dirCache = dircache.New(f.root, rootFolderID, f)

	if err := f.resolveRoot(ctx, rootFolderID); err != nil {
		if err == fs.ErrorIsFile {
			return f, err
		}
		return nil, err
	}
	return f, nil
}

func readOptions(m configmap.Mapper) (Options, error) {
	opt := new(Options)
	if err := configstruct.Set(m, opt); err != nil {
		return Options{}, err
	}

	opt.ValidationKey = revealValidationKey(opt.ValidationKey)
	opt.JSessionID = revealJSessionID(opt.JSessionID)
	opt.DeviceID = normalizeDeviceID(opt.DeviceID)
	opt.APIURL = strings.TrimRight(opt.APIURL, "/")
	opt.UploadURL = strings.TrimRight(opt.UploadURL, "/")

	if err := opt.validate(); err != nil {
		return Options{}, err
	}
	return *opt, nil
}

func (opt Options) validate() error {
	if opt.ValidationKey == "" || opt.JSessionID == "" {
		return errors.New("O2 Cloud browser session credentials missing; run \"rclone config reconnect\" and paste validationKey and JSESSIONID from a logged-in browser")
	}
	if opt.DeviceID == "" {
		return errors.New("O2 Cloud device_id missing; copy omhls.fingerprintKey from browser local storage for cloud.o2online.es")
	}
	return nil
}

func parsePath(root string) string {
	return strings.Trim(root, "/")
}

func newHTTPClient(ctx context.Context) *http.Client {
	jar, _ := cookiejar.New(nil)
	client := fshttp.NewClient(ctx)
	client.Jar = jar
	return client
}

func newPacer(ctx context.Context) *fs.Pacer {
	return fs.NewPacer(ctx, pacer.NewDefault(
		pacer.MinSleep(minSleep),
		pacer.MaxSleep(maxSleep),
		pacer.DecayConstant(decayConstant),
	))
}

func (f *Fs) fillFeatures(ctx context.Context) {
	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
		ReadMimeType:            true,
		Purge:                   f.Purge,
		Move:                    f.Move,
		About:                   f.About,
	}).Fill(ctx, f)
}

func (f *Fs) configuredRootID(ctx context.Context) (string, error) {
	if f.opt.RootFolderID != "" {
		return f.opt.RootFolderID, nil
	}

	id, err := f.readRootFolderID(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to discover root folder id: %w", err)
	}

	rootFolderID := strconv.FormatInt(id, 10)
	fs.Debugf(f, "Discovered O2 root folder id %s", rootFolderID)
	return rootFolderID, nil
}

func (f *Fs) resolveRoot(ctx context.Context, rootFolderID string) error {
	if err := f.dirCache.FindRoot(ctx, false); err == nil {
		return nil
	}

	newRoot, remote := dircache.SplitPath(f.root)
	tempF := *f
	tempF.root = newRoot
	tempF.dirCache = dircache.New(newRoot, rootFolderID, &tempF)

	if err := tempF.dirCache.FindRoot(ctx, false); err != nil {
		return nil
	}
	if _, err := tempF.NewObject(ctx, remote); err != nil {
		if err == fs.ErrorObjectNotFound {
			return nil
		}
		return err
	}

	f.dirCache = tempF.dirCache
	f.root = tempF.root
	return fs.ErrorIsFile
}

// Name of the remote.
func (f *Fs) Name() string { return f.name }

// Root of the remote.
func (f *Fs) Root() string { return f.root }

// String returns a description of the FS.
func (f *Fs) String() string { return fmt.Sprintf("O2 Cloud root %q", f.root) }

// Precision returns the modtime precision.
func (f *Fs) Precision() time.Duration { return time.Millisecond }

// Hashes returns supported hashes.
func (f *Fs) Hashes() hash.Set { return hash.Set(hash.None) }

// Features returns optional features.
func (f *Fs) Features() *fs.Features { return f.features }

var (
	_ fs.Fs        = (*Fs)(nil)
	_ fs.Info      = (*Fs)(nil)
	_ fs.Abouter   = (*Fs)(nil)
	_ fs.Mover     = (*Fs)(nil)
	_ fs.Purger    = (*Fs)(nil)
	_ fs.Object    = (*Object)(nil)
	_ fs.DirEntry  = (*Object)(nil)
	_ fs.MimeTyper = (*Object)(nil)
)
