// Package api contains O2 Cloud API types.
package api

// Envelope is the common top-level response shape.
type Envelope struct {
	Data         Data   `json:"data"`
	Success      string `json:"success"`
	ID           int64  `json:"id"`
	LastUpdate   int64  `json:"lastupdate"`
	ResponseTime int64  `json:"responsetime"`
	Error        *Error `json:"error"`
}

// Error is an O2 Cloud API error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

// Data carries response payloads.
type Data struct {
	Folder  *Folder  `json:"folder"`
	Folders []Folder `json:"folders"`
	Media   []Media  `json:"media"`
	Quota   int64    `json:"quota"`
	Free    int64    `json:"free"`
	Used    int64    `json:"used"`
	Deleted int64    `json:"softdeleted"`
	NoLimit bool     `json:"nolimit"`

	ValidationKey string `json:"validationkey"`
}

// Folder is a folder metadata item.
type Folder struct {
	Name       string `json:"name"`
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	Magic      bool   `json:"magic"`
	Offline    bool   `json:"offline"`
	ParentID   int64  `json:"parentid"`
	Date       int64  `json:"date"`
	LastUpdate int64  `json:"lastupdate"`
}

// Media is a file/media metadata item.
type Media struct {
	ID               string `json:"id"`
	Date             int64  `json:"date"`
	MediaType        string `json:"mediatype"`
	Status           string `json:"status"`
	UserID           string `json:"userid"`
	URL              string `json:"url"`
	CreationDate     int64  `json:"creationdate"`
	ModificationDate int64  `json:"modificationdate"`
	Uploaded         int64  `json:"uploaded"`
	Size             int64  `json:"size"`
	Name             string `json:"name"`
	ETag             string `json:"etag"`
	Folder           int64  `json:"folderid"`
	Favorite         bool   `json:"favorite"`
	Shared           bool   `json:"shared"`
	Origin           Origin `json:"origin"`
	UploadedDeviceID string `json:"uploadeddeviceid"`
}

// Origin describes where a media item came from.
type Origin struct {
	Name string `json:"name"`
}

// UploadResponse is returned by the upload host.
type UploadResponse struct {
	Success      string `json:"success"`
	ID           string `json:"id"`
	Status       string `json:"status"`
	ETag         string `json:"etag"`
	ResponseTime int64  `json:"responsetime"`
	Type         string `json:"type"`
	Error        *Error `json:"error"`
}
