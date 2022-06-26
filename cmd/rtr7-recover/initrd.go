// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	cpio "github.com/cavaliercoder/go-cpio"
	"github.com/rtr7/tools/internal/e2fsprogs"
)

func storeInCpio(w *cpio.Writer, fn string) error {
	f, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	hdr, err := cpio.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	if err := w.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.Copy(w, f); err != nil {
		return err
	}

	return err
}

func makeInitrd() ([]byte, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("could not locate source using runtime.Caller(0)")
	}

	tmpdir, err := ioutil.TempDir("", "rtr7-recover")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpdir)

	// We build rtr7-recovery-init with the working directory set to the
	// directory from which rtr7-recovery was built. This could either be a git
	// working copy, or a $GOPATH/pkg/mod directory when installed via the go
	// tool.
	compile := exec.Command("go",
		"build",
		// -buildvcs fails when running as sudo, because then calls to git fail,
		// because the git directory is owned by a different user (considered
		// unsafe).
		"-buildvcs=false",
		"-o", filepath.Join(tmpdir, "rtr7-recovery-init"),
		"github.com/rtr7/tools/cmd/rtr7-recovery-init")
	compile.Dir = filepath.Dir(file)
	compile.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		// rtr7-recovery might be running on darwin/arm64.
		"GOARCH=amd64",
		"GOOS=linux",
		// Prevent network access in all cases to ensure rtr7-recovery-init can
		// always be built without network access.
		"GOPROXY=off")
	compile.Stderr = os.Stderr
	log.Printf("building github.com/rtr7/tools/cmd/rtr7-recovery-init in %s", compile.Dir)
	if err := compile.Run(); err != nil {
		return nil, fmt.Errorf("%v: %v", compile.Args, err)
	}

	var buf bytes.Buffer
	w := cpio.NewWriter(&buf)

	for _, dir := range []string{"perm", "proc"} {
		hdr := &cpio.Header{
			Name:    dir + "/",
			Mode:    0755 | cpio.ModeDir,
			ModTime: time.Now(),
		}
		if err := w.WriteHeader(hdr); err != nil {
			return nil, err
		}
	}

	for path, b := range e2fsprogs.Bundled {
		hdr := &cpio.Header{
			Name:    filepath.Base(path),
			Mode:    0755 | cpio.ModeRegular,
			ModTime: time.Now(),
			Size:    int64(len(b)),
		}
		if err := w.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := w.Write(b); err != nil {
			return nil, err
		}
	}

	if err := storeInCpio(w, filepath.Join(tmpdir, "rtr7-recovery-init")); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
