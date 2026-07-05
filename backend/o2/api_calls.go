package o2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rclone/rclone/backend/o2/api"
	"github.com/rclone/rclone/fs"
)

func (f *Fs) readRootFolderID(ctx context.Context) (int64, error) {
	var env api.Envelope
	err := f.doJSON(ctx, http.MethodGet, f.opt.APIURL+"/sapi/media/folder/root?action=get", nil, &env)
	if err != nil {
		return 0, err
	}
	if env.Data.Folder != nil && env.Data.Folder.ID != 0 {
		return env.Data.Folder.ID, nil
	}
	if len(env.Data.Folders) > 0 {
		return env.Data.Folders[0].ID, nil
	}
	return 0, errors.New("root folder id missing in response")
}

// About gets quota information.
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	var env api.Envelope
	if err := f.doJSON(ctx, http.MethodGet, f.opt.APIURL+"/sapi/media?action=get-storage-space&softdeleted=true", nil, &env); err != nil {
		return nil, fmt.Errorf("failed to read O2 quota: %w", err)
	}

	usage := &fs.Usage{
		Used:    fs.NewUsageValue(env.Data.Used),
		Trashed: fs.NewUsageValue(env.Data.Deleted),
		Free:    fs.NewUsageValue(env.Data.Free),
	}
	if !env.Data.NoLimit {
		usage.Total = fs.NewUsageValue(env.Data.Quota)
	}

	fs.Debugf(f, "Read O2 quota used=%d free=%d trashed=%d total=%d nolimit=%v", env.Data.Used, env.Data.Free, env.Data.Deleted, env.Data.Quota, env.Data.NoLimit)
	return usage, nil
}

func (f *Fs) listFolders(ctx context.Context, folderID int64) ([]api.Folder, error) {
	var env api.Envelope
	u := fmt.Sprintf("%s/sapi/media/folder?action=list&parentid=%d&limit=200", f.opt.APIURL, folderID)
	if err := f.doJSON(ctx, http.MethodGet, u, nil, &env); err != nil {
		return nil, err
	}
	fs.Debugf(f, "Listed %d O2 folders under folderID=%d", len(env.Data.Folders), folderID)
	return env.Data.Folders, nil
}

func (f *Fs) listMedia(ctx context.Context, folderID int64) ([]api.Media, error) {
	in := map[string]any{"data": map[string]any{"fields": defaultListFields}}
	var env api.Envelope
	u := fmt.Sprintf("%s/sapi/media?action=get&folderid=%d&limit=200", f.opt.APIURL, folderID)
	if err := f.doJSON(ctx, http.MethodPost, u, in, &env); err != nil {
		return nil, err
	}
	fs.Debugf(f, "Listed %d O2 media items under folderID=%d", len(env.Data.Media), folderID)
	return env.Data.Media, nil
}

func (f *Fs) createFolder(ctx context.Context, parentID int64, leaf string) (api.Folder, error) {
	in := map[string]any{"data": map[string]any{
		"magic":    false,
		"offline":  false,
		"name":     f.opt.Enc.FromStandardName(leaf),
		"parentid": parentID,
	}}
	var env api.Envelope
	if err := f.doJSON(ctx, http.MethodPost, f.opt.APIURL+"/sapi/media/folder?action=save", in, &env); err != nil {
		return api.Folder{}, err
	}

	folder := api.Folder{Name: leaf, ID: env.ID, ParentID: parentID, LastUpdate: env.LastUpdate, Date: env.LastUpdate}
	if env.Data.Folder != nil {
		folder = *env.Data.Folder
	}
	fs.Debugf(f, "Created O2 folder name=%q id=%d parentID=%d", leaf, folder.ID, parentID)
	return folder, nil
}

func (f *Fs) saveMediaMetadata(ctx context.Context, id, leaf string, folderID int64) (api.Media, error) {
	numericID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return api.Media{}, err
	}

	payload := map[string]any{"data": map[string]any{
		"id":       numericID,
		"name":     f.opt.Enc.FromStandardName(leaf),
		"folderid": folderID,
	}}
	data, err := json.Marshal(payload)
	if err != nil {
		return api.Media{}, err
	}

	form := url.Values{}
	form.Set("data", string(data))
	fs.Debugf(f, "Saving O2 media metadata id=%s name=%q folderID=%d", id, leaf, folderID)
	if err := f.doForm(ctx, http.MethodPost, f.opt.APIURL+"/sapi/upload/file?action=save-metadata", form, nil); err != nil {
		return api.Media{}, err
	}

	media, err := f.waitMedia(ctx, id)
	if err != nil {
		return api.Media{}, err
	}
	media.Name = f.opt.Enc.FromStandardName(leaf)
	media.Folder = folderID
	return media, nil
}

func (f *Fs) getMedia(ctx context.Context, id string) (api.Media, error) {
	numericID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return api.Media{}, err
	}

	in := map[string]any{"data": map[string]any{
		"ids":    []int64{numericID},
		"fields": fullMediaFields,
	}}
	var env api.Envelope
	if err := f.doJSON(ctx, http.MethodPost, f.opt.APIURL+"/sapi/media?action=get&origin=omh,dropbox", in, &env); err != nil {
		return api.Media{}, err
	}
	if len(env.Data.Media) == 0 {
		return api.Media{}, fs.ErrorObjectNotFound
	}
	return env.Data.Media[0], nil
}

func (f *Fs) deleteFile(ctx context.Context, id string) error {
	numericID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	in := map[string]any{"data": map[string]any{"files": []int64{numericID}}}
	fs.Debugf(f, "Soft deleting O2 file id=%s", id)
	return f.doJSON(ctx, http.MethodPost, f.opt.APIURL+"/sapi/media/file?action=delete&softdelete=true", in, nil)
}

func (f *Fs) deleteFolder(ctx context.Context, id int64) error {
	in := map[string]any{"data": map[string]any{"ids": []int64{id}}}
	fs.Debugf(f, "Soft deleting O2 folder id=%d", id)
	return f.doJSON(ctx, http.MethodPost, f.opt.APIURL+"/sapi/media/folder?action=softdelete", in, nil)
}

func (f *Fs) waitMedia(ctx context.Context, id string) (api.Media, error) {
	var lastErr error
	for i := 0; i < 10; i++ {
		media, err := f.getMedia(ctx, id)
		if err == nil {
			return media, nil
		}
		lastErr = err
		if err != fs.ErrorObjectNotFound {
			return api.Media{}, err
		}

		fs.Debugf(f, "O2 media id=%s not visible yet after upload; waiting", id)
		if err := sleepWithContext(ctx, time.Duration(i+1)*time.Second); err != nil {
			return api.Media{}, err
		}
	}
	return api.Media{}, lastErr
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(duration):
		return nil
	}
}

var defaultListFields = []string{"name", "modificationdate", "size", "thumbnails", "videometadata", "audiometadata", "favorite", "shared", "etag"}

var fullMediaFields = []string{"creationdate", "postingdate", "name", "size", "thumbnails", "viewurl", "url", "videometadata", "audiometadata", "shared", "exported", "favorite", "origin", "folderid", "labels", "modificationdate", "uploadeddeviceid", "uploaded", "etag"}
