package o2

import (
	"context"
	"errors"
	"io"
	"path"
	"strconv"

	"github.com/rclone/rclone/fs"
)

// FindLeaf finds a directory leaf in pathID.
func (f *Fs) FindLeaf(ctx context.Context, pathID, leaf string) (pathIDOut string, found bool, err error) {
	parentID, err := parseFolderID(pathID)
	if err != nil {
		return "", false, err
	}

	folders, err := f.listFolders(ctx, parentID)
	if err != nil {
		return "", false, err
	}
	for _, folder := range folders {
		if f.opt.Enc.ToStandardName(folder.Name) == leaf {
			return strconv.FormatInt(folder.ID, 10), true, nil
		}
	}
	return "", false, nil
}

// CreateDir makes a directory under pathID.
func (f *Fs) CreateDir(ctx context.Context, pathID, leaf string) (newID string, err error) {
	parentID, err := parseFolderID(pathID)
	if err != nil {
		return "", err
	}

	folder, err := f.createFolder(ctx, parentID, leaf)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(folder.ID, 10), nil
}

// List lists the objects and directories in dir.
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	folderID, err := f.folderID(ctx, dir)
	if err != nil {
		return nil, err
	}

	folders, err := f.listFolders(ctx, folderID)
	if err != nil {
		return nil, err
	}
	entries := make(fs.DirEntries, 0, len(folders))
	for _, folder := range folders {
		remote := path.Join(dir, f.opt.Enc.ToStandardName(folder.Name))
		entries = append(entries, fs.NewDir(remote, msToTime(folder.Date)).SetID(strconv.FormatInt(folder.ID, 10)))
		f.dirCache.Put(remote, strconv.FormatInt(folder.ID, 10))
	}

	media, err := f.listMedia(ctx, folderID)
	if err != nil {
		return nil, err
	}
	for _, item := range media {
		remote := path.Join(dir, f.opt.Enc.ToStandardName(item.Name))
		entries = append(entries, f.newObjectFromMedia(remote, item, folderID))
	}
	return entries, nil
}

// NewObject finds an object by remote.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	leaf, dirID, err := f.dirCache.FindPath(ctx, remote, false)
	if err != nil {
		if err == fs.ErrorDirNotFound {
			return nil, fs.ErrorObjectNotFound
		}
		return nil, err
	}

	folderID, err := parseFolderID(dirID)
	if err != nil {
		return nil, err
	}

	media, err := f.listMedia(ctx, folderID)
	if err != nil {
		return nil, err
	}
	for _, item := range media {
		if f.opt.Enc.ToStandardName(item.Name) == leaf {
			return f.newObjectFromMedia(f.objectRemote(remote, dirID, item.Name), item, folderID), nil
		}
	}
	return nil, fs.ErrorObjectNotFound
}

// Move moves an object server-side by updating its metadata.
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't move - not same O2 remote")
		return nil, fs.ErrorCantMove
	}

	leaf, folderID, err := f.parentFolderID(ctx, remote, true)
	if err != nil {
		return nil, err
	}

	media, err := f.saveMediaMetadata(ctx, srcObj.id, leaf, folderID)
	if err != nil {
		return nil, err
	}

	fs.Debugf(f, "Moved O2 object id=%s from=%q to=%q folderID=%d", srcObj.id, srcObj.remote, remote, folderID)
	srcObj.fs.dirCache.FlushDir(parentDir(srcObj.remote))
	return f.newObjectFromMedia(remote, media, folderID), nil
}

// Put uploads an object.
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	existing, err := f.NewObject(ctx, src.Remote())
	if err == nil {
		return existing, existing.Update(ctx, in, src, options...)
	}
	if err != fs.ErrorObjectNotFound {
		return nil, err
	}
	return f.upload(ctx, in, src, options...)
}

// Mkdir creates a directory.
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	_, err := f.dirCache.FindDir(ctx, dir, true)
	return err
}

// Rmdir removes an empty directory.
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	if dir == "" && f.root == "" {
		return errors.New("can't remove root directory")
	}

	folderID, err := f.folderID(ctx, dir)
	if err != nil {
		return err
	}
	if entries, err := f.List(ctx, dir); err != nil {
		return err
	} else if len(entries) != 0 {
		return fs.ErrorDirectoryNotEmpty
	}
	if err := f.deleteFolder(ctx, folderID); err != nil {
		return err
	}
	f.dirCache.FlushDir(dir)
	return nil
}

// Purge removes a directory and all its contents.
func (f *Fs) Purge(ctx context.Context, dir string) error {
	if dir == "" && f.root == "" {
		return errors.New("can't purge root directory")
	}

	folderID, err := f.folderID(ctx, dir)
	if err != nil {
		return err
	}
	if err := f.deleteFolder(ctx, folderID); err != nil {
		return err
	}
	f.dirCache.FlushDir(dir)
	fs.Debugf(f, "Purged O2 directory dir=%q folderID=%d", dir, folderID)
	return nil
}

func (f *Fs) folderID(ctx context.Context, dir string) (int64, error) {
	dirID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return 0, err
	}
	return parseFolderID(dirID)
}

func (f *Fs) parentFolderID(ctx context.Context, remote string, create bool) (leaf string, folderID int64, err error) {
	leaf, dirID, err := f.dirCache.FindPath(ctx, remote, create)
	if err != nil {
		return "", 0, err
	}
	folderID, err = parseFolderID(dirID)
	return leaf, folderID, err
}

func (f *Fs) objectRemote(remote, dirID, apiName string) string {
	dir, ok := f.dirCache.GetInv(dirID)
	if !ok {
		dir = parentDir(remote)
	}
	return path.Join(dir, f.opt.Enc.ToStandardName(apiName))
}

func parseFolderID(id string) (int64, error) {
	return strconv.ParseInt(id, 10, 64)
}

func parentDir(remote string) string {
	dir := path.Dir(remote)
	if dir == "." {
		return ""
	}
	return dir
}
