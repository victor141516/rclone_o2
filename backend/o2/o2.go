// Package o2 provides an interface to O2 Cloud.
package o2

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
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

	minSleep      = 10 * time.Millisecond
	maxSleep      = 2 * time.Second
	decayConstant = 2
)

func init() {
	fs.Register(&fs.RegInfo{
		Name:        "o2",
		Description: "O2 Cloud",
		NewFs:       NewFs,
		Config:      Config,
		Options: []fs.Option{{
			Name:    "provider",
			Help:    "Cloud provider to connect to.",
			Default: providerO2,
			Examples: []fs.OptionExample{{
				Value: providerO2,
				Help:  "O2 Cloud",
			}, {
				Value: providerMovistar,
				Help:  "Movistar Cloud",
			}},
		}, {
			Name:     "phone_number",
			Help:     "Phone number used to receive the login SMS.\n\nUse international format, for example +34600111222, or a Spanish mobile number.",
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
	Provider             string               `config:"provider"`
	PhoneNumber          string               `config:"phone_number"`
	ValidationKey        string               `config:"validation_key"`
	JSessionID           string               `config:"jsessionid"`
	DeviceID             string               `config:"device_id"`
	AccessToken          string               `config:"access_token"`
	RefreshToken         string               `config:"refresh_token"`
	OAuthExpiresIn       string               `config:"oauth_expires_in"`
	OAuthLastRefreshDate int64                `config:"oauth_last_refresh_date"`
	RootFolderID         string               `config:"root_folder_id"`
	APIURL               string               `config:"api_url"`
	UploadURL            string               `config:"upload_url"`
	Enc                  encoder.MultiEncoder `config:"encoding"`
}

// Fs represents an O2 Cloud remote.
type Fs struct {
	name     string
	root     string
	opt      Options
	m        configmap.Mapper
	features *fs.Features
	client   *http.Client
	pacer    *fs.Pacer
	dirCache *dircache.DirCache
	authMu   sync.Mutex
}

// Object describes an O2 Cloud object.
type Object struct {
	fs        *Fs
	remote    string
	id        string
	size      int64
	modTime   time.Time
	mimeType  string
	mediaType string
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
		m:      m,
		client: newHTTPClient(ctx),
		pacer:  newPacer(ctx),
	}
	f.fillFeatures(ctx)

	rootFolderID, err := f.configuredRootID(ctx)
	if err != nil {
		return nil, err
	}
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
	opt, err := readOptionsUnchecked(m)
	if err != nil {
		return Options{}, err
	}
	if err := opt.validate(); err != nil {
		return Options{}, err
	}
	return opt, nil
}

func readOptionsUnchecked(m configmap.Mapper) (Options, error) {
	opt := new(Options)
	if err := configstruct.Set(m, opt); err != nil {
		return Options{}, err
	}

	opt.PhoneNumber = normalizePhoneNumber(opt.PhoneNumber)
	opt.Provider = normalizeProvider(opt.Provider)
	opt.ValidationKey = revealValidationKey(opt.ValidationKey)
	opt.JSessionID = revealJSessionID(opt.JSessionID)
	opt.AccessToken = revealIfObscured(opt.AccessToken)
	opt.RefreshToken = revealIfObscured(opt.RefreshToken)
	opt.DeviceID = normalizeDeviceID(opt.DeviceID)
	if opt.APIURL == "" || (opt.Provider == providerMovistar && opt.APIURL == defaultAPIURL) {
		opt.APIURL, _ = providerDefaults(opt.Provider)
	}
	if opt.UploadURL == "" || (opt.Provider == providerMovistar && opt.UploadURL == defaultUploadURL) {
		_, opt.UploadURL = providerDefaults(opt.Provider)
	}
	opt.APIURL = strings.TrimRight(opt.APIURL, "/")
	opt.UploadURL = strings.TrimRight(opt.UploadURL, "/")

	return *opt, nil
}

func (opt Options) validate() error {
	profile, err := opt.provider()
	if err != nil {
		return err
	}
	if opt.PhoneNumber == "" {
		return fmt.Errorf("%s phone number missing; run \"rclone config reconnect\" to authenticate with SMS", profile.Description)
	}
	if opt.AccessToken == "" || opt.RefreshToken == "" {
		return fmt.Errorf("%s renewable OAuth credentials missing; run \"rclone config reconnect\" to authenticate with SMS", profile.Description)
	}
	if opt.ValidationKey == "" || opt.JSessionID == "" {
		return fmt.Errorf("%s session missing; run \"rclone config reconnect\" to authenticate with SMS", profile.Description)
	}
	if opt.DeviceID == "" {
		return fmt.Errorf("%s device id missing; run \"rclone config reconnect\" to authenticate with SMS", profile.Description)
	}
	return nil
}

func parsePath(root string) string {
	return strings.Trim(root, "/")
}

func newHTTPClient(ctx context.Context) *http.Client {
	return fshttp.NewClient(ctx)
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
		DirMove:                 f.DirMove,
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
	tempF := &Fs{
		name:   f.name,
		root:   newRoot,
		opt:    f.opt,
		m:      f.m,
		client: f.client,
		pacer:  f.pacer,
	}
	tempF.dirCache = dircache.New(newRoot, rootFolderID, tempF)

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
func (f *Fs) Precision() time.Duration { return time.Second }

// Hashes returns supported hashes.
func (f *Fs) Hashes() hash.Set { return hash.Set(hash.None) }

// Features returns optional features.
func (f *Fs) Features() *fs.Features { return f.features }

var (
	_ fs.Fs        = (*Fs)(nil)
	_ fs.Info      = (*Fs)(nil)
	_ fs.Abouter   = (*Fs)(nil)
	_ fs.Mover     = (*Fs)(nil)
	_ fs.DirMover  = (*Fs)(nil)
	_ fs.Purger    = (*Fs)(nil)
	_ fs.Object    = (*Object)(nil)
	_ fs.DirEntry  = (*Object)(nil)
	_ fs.MimeTyper = (*Object)(nil)
)
