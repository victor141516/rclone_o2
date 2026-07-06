package o2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/rclone/rclone/backend/o2/api"
	"github.com/rclone/rclone/fs"
)

var multipartQuoteReplacer = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func (f *Fs) upload(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	if err := f.refreshUploadSessionBeforeUpload(ctx); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fs.Debugf(f, "O2 session refresh before upload failed; continuing with existing session: %v", err)
	}

	leaf, folderID, err := f.parentFolderID(ctx, src.Remote(), true)
	if err != nil {
		return nil, err
	}

	mimeType := fs.MimeType(ctx, src)
	if mimeType == "" {
		mimeType = fs.MimeTypeFromName(src.Remote())
	}

	apiLeaf := f.opt.Enc.FromStandardName(leaf)
	metadata, err := uploadMetadata(apiLeaf, folderID, src.Size())
	if err != nil {
		return nil, err
	}

	req, err := f.newUploadRequest(ctx, metadata, apiLeaf, src.Size(), mimeType, in)
	if err != nil {
		return nil, err
	}

	uploadResp, err := f.doUpload(ctx, req, src.Remote(), folderID, src.Size())
	if err != nil {
		return nil, err
	}

	fs.Debugf(f, "Uploaded O2 object remote=%q id=%s status=%s", src.Remote(), uploadResp.ID, uploadResp.Status)
	if uploadResp.ID == "" {
		return nil, errors.New("O2 upload response missing id")
	}

	return f.newObjectFromUpload(ctx, src, uploadResp, mimeType), nil
}

func uploadMetadata(name string, folderID, size int64) ([]byte, error) {
	return json.Marshal(map[string]any{"data": map[string]any{
		"name":             name,
		"size":             size,
		"folderid":         folderID,
		"modificationdate": "",
	}})
}

func (f *Fs) newUploadRequest(ctx context.Context, metadata []byte, fileName string, size int64, mimeType string, in io.Reader) (*http.Request, error) {
	u, err := f.addValidationKey(f.opt.UploadURL + "/sapi/upload?action=save&acceptasynchronous=true")
	if err != nil {
		return nil, err
	}

	body, contentType, contentLength, err := newUploadBody(metadata, fileName, size, mimeType, in)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		closeUploadBody(body)
		return nil, err
	}
	f.addCommonHeaders(req)
	f.addUploadCookie(req)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "*/*")
	addFetchHeaders(req, "same-site")
	if contentLength >= 0 {
		req.ContentLength = contentLength
	}

	return req, nil
}

func newUploadBody(metadata []byte, fileName string, size int64, mimeType string, in io.Reader) (io.Reader, string, int64, error) {
	if size < 0 {
		return newStreamingUploadBody(metadata, fileName, mimeType, in)
	}

	var head bytes.Buffer
	mw := multipart.NewWriter(&head)
	if err := mw.WriteField("data", string(metadata)); err != nil {
		return nil, "", 0, err
	}
	if _, err := createUploadFilePart(mw, fileName, mimeType); err != nil {
		return nil, "", 0, err
	}

	tail := []byte("\r\n--" + mw.Boundary() + "--\r\n")
	body := io.MultiReader(bytes.NewReader(head.Bytes()), in, bytes.NewReader(tail))
	contentLength := int64(head.Len()) + size + int64(len(tail))
	return body, mw.FormDataContentType(), contentLength, nil
}

func newStreamingUploadBody(metadata []byte, fileName, mimeType string, in io.Reader) (io.Reader, string, int64, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go streamUpload(pw, mw, metadata, fileName, mimeType, in)
	return pr, mw.FormDataContentType(), -1, nil
}

func closeUploadBody(body io.Reader) {
	if closer, ok := body.(io.Closer); ok {
		_ = closer.Close()
	}
}

func streamUpload(pw *io.PipeWriter, mw *multipart.Writer, metadata []byte, fileName, mimeType string, in io.Reader) {
	if err := writeUploadParts(mw, metadata, fileName, mimeType, in); err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	if err := mw.Close(); err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	_ = pw.Close()
}

func writeUploadParts(mw *multipart.Writer, metadata []byte, fileName, mimeType string, in io.Reader) error {
	if err := mw.WriteField("data", string(metadata)); err != nil {
		return err
	}
	part, err := createUploadFilePart(mw, fileName, mimeType)
	if err != nil {
		return err
	}
	_, err = io.Copy(part, in)
	return err
}

func createUploadFilePart(mw *multipart.Writer, fileName, mimeType string) (io.Writer, error) {
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="file"; filename="`+escapeMultipartQuotes(fileName)+`"`)
	header.Set("Content-Type", uploadFileContentType(mimeType))
	return mw.CreatePart(header)
}

func uploadFileContentType(mimeType string) string {
	if mimeType == "" {
		return "application/octet-stream"
	}
	return mimeType
}

func escapeMultipartQuotes(s string) string {
	return multipartQuoteReplacer.Replace(s)
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

	if !successful(resp) {
		return uploadResp, parseAPIError(resp)
	}
	err = decodeAPIResponse(resp, &uploadResp)
	return uploadResp, err
}

func (f *Fs) newObjectFromUpload(ctx context.Context, src fs.ObjectInfo, uploadResp api.UploadResponse, mimeType string) *Object {
	return &Object{
		fs:        f,
		remote:    src.Remote(),
		id:        uploadResp.ID,
		size:      src.Size(),
		modTime:   src.ModTime(ctx),
		mimeType:  mimeType,
		mediaType: uploadResp.Type,
	}
}
