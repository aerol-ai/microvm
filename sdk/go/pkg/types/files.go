package types

import "os"

// DefaultListLimit is the entry cap ListFiles sends when ListFilesOptions
// gives none. A listing past it comes back with Truncated set.
const DefaultListLimit = 10000

// FileInfo describes one file, folder or symlink in a sandbox.
type FileInfo struct {
	// Name is the last part of Path.
	Name string `json:"name"`
	// Path is the full path in the sandbox.
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
	// Size is in bytes.
	Size int64 `json:"size"`
	// Mode is the type and permission string, such as "-rw-r--r--".
	Mode string `json:"mode"`
	// Permissions is the octal permission bits, such as "0644".
	Permissions string `json:"permissions"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
	// ModTime is the last change time, RFC 3339 in UTC.
	ModTime string `json:"mod_time"`
	// SymlinkTarget is where a symlink points. Set only on ListFiles
	// entries: GetFileInfo follows a symlink and describes what it names.
	SymlinkTarget string `json:"symlink_target,omitempty"`
}

// FileList is the result of ListFiles. Truncated means the listing reached
// its Limit and stopped; more entries exist.
type FileList struct {
	Entries   []FileInfo `json:"entries"`
	Truncated bool       `json:"truncated"`
}

// ListFilesOptions controls ListFiles. The zero value lists one level with
// a cap of DefaultListLimit entries.
type ListFilesOptions struct {
	// Depth is how many levels to go down: 1 (the default) is the folder's
	// own entries. Symlinked folders are listed but never entered.
	Depth int
	// Limit is the most entries to return; 0 means DefaultListLimit.
	Limit int
}

// DeleteFileOptions controls DeleteFile.
type DeleteFileOptions struct {
	// Recursive deletes a folder and everything in it. Without it, a folder
	// is refused with a 409 conflict.
	Recursive bool
}

// MakeDirOptions controls MakeDir.
type MakeDirOptions struct {
	// Parents makes missing parent folders, and succeeds when the folder is
	// already there (like mkdir -p). Without it the parent must exist and
	// the folder must not.
	Parents bool
	// Mode is the new folder's permissions, such as 0o750; 0 means 0755.
	// With Parents, an existing folder is changed to Mode only when Mode is
	// set.
	Mode os.FileMode
}

// MoveFileOptions controls MoveFile.
type MoveFileOptions struct {
	// Overwrite replaces an existing destination file. Without it the move
	// is refused with a 409 conflict when the destination exists.
	Overwrite bool
}

// CopyFileOptions controls CopyFile.
type CopyFileOptions struct {
	// Overwrite replaces an existing destination file.
	Overwrite bool
	// Recursive copies a folder and everything in it, keeping modes and
	// symlinks. Without it, a folder is refused with a 409 conflict.
	Recursive bool
}

// FileMatch is one line FindInFiles found.
type FileMatch struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Content string `json:"content"`
}

// UploadFileOptions controls how an upload writes its file. The zero value
// is a plain upload: missing folders are made and an existing file is
// replaced in place.
type UploadFileOptions struct {
	// Append adds to the end of the file instead of replacing it.
	Append bool
	// CreateOnly writes only if the file does not exist yet. Otherwise the
	// upload fails with a 412, and of two uploads racing for one new path
	// exactly one wins.
	CreateOnly bool
	// Atomic writes a temp file and renames it into place, so a reader sees
	// the old file or the new one, never half of it. It cannot be combined
	// with Append.
	Atomic bool
	// Mode is the file's permissions after the write, such as 0o600. 0
	// leaves an existing file's permissions and gives a new file 0644.
	Mode os.FileMode
}
