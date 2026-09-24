package route

import http "github.com/metacubex/http"

type hakoUserspaceFileSystem struct{ inner http.FileSystem }

func (fsys hakoUserspaceFileSystem) Open(name string) (http.File, error) {
	file, err := fsys.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return hakoUserspaceFile{file}, nil
}

type hakoUserspaceFile struct{ http.File }
