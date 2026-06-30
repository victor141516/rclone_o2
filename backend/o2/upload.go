package o2

import (
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/rclone/rclone/backend/o2/api"
	"github.com/rclone/rclone/fs"
)

func (f *Fs) upload(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	leaf, folderID, err := f.parentFolderID(ctx, src.Remote(), true)
	if err != nil {
		return nil, err
	}

	mimeType := fs.MimeType(ctx, src)
	if mimeType == "" {
		mimeType = fs.MimeTypeFromName(src.Remote())
	}

	apiLeaf := f.opt.Enc.FromStandardName(leaf)
	metadata, err := uploadMetadata(apiLeaf, folderID, src.Size(), mimeType)
	if err != nil {
		return nil, err
	}

	req, stream, err := f.newUploadRequest(ctx)
	if err != nil {
		return nil, err
	}
	go stream(metadata, apiLeaf, in)

	uploadResp, err := f.doUpload(ctx, req, src.Remote(), folderID, src.Size())
	if err != nil {
		return nil, err
	}

	fs.Debugf(f, "Uploaded O2 object remote=%q id=%s status=%s", src.Remote(), uploadResp.ID, uploadResp.Status)
	if err := f.waitUploadValidated(ctx, uploadResp.ID); err != nil {
		fs.Debugf(f, "Upload validation did not complete cleanly for id=%s: %v", uploadResp.ID, err)
	}

	media, err := f.waitMedia(ctx, uploadResp.ID)
	if err != nil {
		return nil, err
	}
	return f.newObjectFromMedia(src.Remote(), media, folderID), nil
}

func uploadMetadata(name string, folderID, size int64, mimeType string) ([]byte, error) {
	return json.Marshal(map[string]any{"data": map[string]any{
		"name":             name,
		"size":             size,
		"modificationdate": "",
		"contenttype":      mimeType,
		"folderid":         folderID,
	}})
}

type uploadStreamer func(metadata []byte, fileName string, in io.Reader)

func (f *Fs) newUploadRequest(ctx context.Context) (*http.Request, uploadStreamer, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	u, err := f.addValidationKey(f.opt.UploadURL + "/sapi/upload?action=save")
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, nil, err
	}
	f.addHeaders(req)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "*/*")

	return req, func(metadata []byte, fileName string, in io.Reader) {
		streamUpload(pw, mw, metadata, fileName, in)
	}, nil
}

func streamUpload(pw *io.PipeWriter, mw *multipart.Writer, metadata []byte, fileName string, in io.Reader) {
	if err := writeUploadParts(mw, metadata, fileName, in); err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	if err := mw.Close(); err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	_ = pw.Close()
}

func writeUploadParts(mw *multipart.Writer, metadata []byte, fileName string, in io.Reader) error {
	if err := mw.WriteField("data", string(metadata)); err != nil {
		return err
	}
	part, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		return err
	}
	_, err = io.Copy(part, in)
	return err
}

func (f *Fs) doUpload(ctx context.Context, req *http.Request, remote string, folderID, size int64) (api.UploadResponse, error) {
	var uploadResp api.UploadResponse
	var resp *http.Response
	err := f.pacer.CallNoRetry(func() (bool, error) {
		fs.Debugf(f, "Uploading O2 object remote=%q folderID=%d size=%d", remote, folderID, size)
		var err error
		resp, err = f.client.Do(req)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		closeResponse(resp)
		return uploadResp, err
	}
	defer fs.CheckClose(resp.Body, &err)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return uploadResp, parseAPIError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		return uploadResp, err
	}
	if uploadResp.Error != nil {
		return uploadResp, &apiError{StatusCode: resp.StatusCode, Code: uploadResp.Error.Code, Message: uploadResp.Error.Message}
	}
	return uploadResp, nil
}
