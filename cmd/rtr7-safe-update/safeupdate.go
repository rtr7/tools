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

// Binary rtr7-safe-update safely updates a router.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/build"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rtr7/tools/internal/updater"
)

var (
	updatesDir = flag.String("updates_dir",
		"/home/michael/router7/updates/",
		"Directory in which a subdirectory with backups, logs, boot/root file system images will be stored")

	buildCommand = flag.String("build_command",
		`GOARCH=amd64 gokr-packer \
	-hostname=router7 \
	-overwrite_boot=${GOKR_DIR}/boot.img \
	-overwrite_mbr=${GOKR_DIR}/mbr.img \
	-overwrite_root=${GOKR_DIR}/root.img \
	-kernel_package=github.com/rtr7/kernel \
	-firmware_package=github.com/rtr7/kernel \
	-gokrazy_pkgs=github.com/gokrazy/gokrazy/cmd/ntp,github.com/gokrazy/gokrazy/cmd/randomd \
	-serial_console=ttyS0,115200n8 \
	github.com/rtr7/router7/cmd/...`,
		"gokr-packer invocation to run (via /bin/sh -c). The GOKR_DIR environment variable is set to the destination directory.")

	hostname = flag.String("hostname",
		"router7",
		"Hostname or IP address to update")

	keepOnlyN = flag.Int("keep_only_n",
		5,
		"Keep only the last N (default 5) updates to conserve disk space. Setting this to -1 keeps all updates forever.")
)

func verifyHealthy() error {
	url := "http://" + *hostname + ":7733/health.json"
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		return fmt.Errorf("%s: unexpected HTTP status code: got %v, want %v", url, got, want)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s: reading body: %v", url, err)
	}
	var reply struct {
		FirstError string `json:"first_error"`
	}
	if err := json.Unmarshal(b, &reply); err != nil {
		return fmt.Errorf("%s: parsing JSON: %v", url, err)
	}
	if reply.FirstError != "" {
		return fmt.Errorf("unhealthy: %v", reply.FirstError)
	}
	return nil // healthy
}

func latestImage() (string, error) {
	f, err := os.Open(*updatesDir)
	if err != nil {
		return "", err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return "", err
	}
	if len(names) < 2 {
		return "", fmt.Errorf("no images found in -image_dir=%q", *updatesDir)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] > names[j] })
	for _, name := range names {
		if fi, err := os.Stat(filepath.Join(*updatesDir, name, "boot.img")); err != nil || fi.Size() == 0 {
			continue
		}
		if fi, err := os.Stat(filepath.Join(*updatesDir, name, "root.img")); err != nil || fi.Size() == 0 {
			continue
		}
		return name, nil
	}
	return "", fmt.Errorf("no subdirectory with non-empty boot.img and root.img found in %q", *updatesDir)
}

func keepOnly(n int) error {
	if n == -1 {
		return nil
	}
	f, err := os.Open(*updatesDir)
	if err != nil {
		return err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("no images found in -image_dir=%q", *updatesDir)
	}
	sort.Strings(names)
	if len(names) <= n {
		return nil // nothing to do
	}
	for _, name := range names[:len(names)-n] {
		fn := filepath.Join(*updatesDir, name)
		log.Printf("deleting %s (keeping only the most recent %d updates)", fn, n)
		if err := os.RemoveAll(fn); err != nil {
			return err
		}
	}
	return nil
}

func storeBackup(dir string) error {
	backupfn := filepath.Join(dir, "backup.tar.gz")
	log.Printf("downloading backup to %s", backupfn)
	url := "http://" + *hostname + ":8077/backup.tar.gz"
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		return fmt.Errorf("%s: unexpected HTTP status code: got %v, want %v", url, got, want)
	}
	f, err := os.Create(backupfn)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Close()
}

func buildImage(dir string) error {
	build := exec.Command("/bin/sh", "-c", *buildCommand)
	build.Env = append(os.Environ(), "GOKR_DIR="+dir)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("%v: %v", build.Args, err)
	}
	return nil
}

func update(dir string) error {
	pwb, err := ioutil.ReadFile(filepath.Join(os.Getenv("HOME"), ".config", "gokrazy", "http-password.txt"))
	if err != nil {
		return err
	}
	pw := strings.TrimSpace(string(pwb))

	root, err := os.Open(filepath.Join(dir, "root.img"))
	if err != nil {
		return err
	}
	defer root.Close()

	boot, err := os.Open(filepath.Join(dir, "boot.img"))
	if err != nil {
		return err
	}
	defer boot.Close()

	mbr, err := os.Open(filepath.Join(dir, "mbr.img"))
	if err != nil {
		return err
	}
	defer mbr.Close()

	baseUrl := "http://gokrazy:" + pw + "@" + *hostname + "/"

	// Start with the root file system because writing to the non-active
	// partition cannot break the currently running system.
	if err := updater.UpdateRoot(baseUrl, root); err != nil {
		return fmt.Errorf("updating root file system: %v", err)
	}

	if err := updater.UpdateBoot(baseUrl, boot); err != nil {
		return fmt.Errorf("updating boot file system: %v", err)
	}

	if err := updater.UpdateMBR(baseUrl, mbr); err != nil {
		return fmt.Errorf("updating MBR: %v", err)
	}

	if err := updater.Switch(baseUrl); err != nil {
		return fmt.Errorf("switching to non-active partition: %v", err)
	}

	if err := updater.Reboot(baseUrl); err != nil {
		return fmt.Errorf("reboot: %v", err)
	}

	return nil
}

func rollback(latest string) error {
	if latest == "" {
		return fmt.Errorf("no latest image found")
	}
	// Figure out the full path so that we can construct a sudo command line
	path, err := exec.LookPath("rtr7-recover")
	if err != nil {
		return err
	}
	recover := exec.Command("sudo",
		"--preserve-env=GOPATH",
		path,
		"-boot="+filepath.Join(*updatesDir, latest, "boot.img"),
		"-root="+filepath.Join(*updatesDir, latest, "root.img"),
		"-mbr="+filepath.Join(*updatesDir, latest, "mbr.img"))
	recover.Env = append(os.Environ(), "GOPATH="+build.Default.GOPATH)
	recover.Stdout = os.Stdout
	recover.Stderr = os.Stderr
	if err := recover.Run(); err != nil {
		return fmt.Errorf("%v: %v", recover.Args, err)
	}
	return nil
}

func logic() error {
	if _, err := os.Stat(*updatesDir); err != nil {
		return fmt.Errorf("stat(-updates_dir): %v", err)
	}

	var buildTimestamp, dir string
	if e := os.Getenv("RTR7_SAFE_UPDATE_REEXEC"); e != "" {
		buildTimestamp = e
		dir = filepath.Join(*updatesDir, buildTimestamp)
	} else {
		buildTimestamp = time.Now().Format(time.RFC3339) // TODO: pass to gokr-packer
		dir = filepath.Join(*updatesDir, buildTimestamp)
		if err := os.Mkdir(dir, 0755); err != nil {
			return err
		}
	}

	if os.Getenv("RTR7_SAFE_UPDATE_REEXEC") == "" {
		log.Printf("redirecting output to %s/{stdout,stderr}.log", dir)
		stdout, err := os.Create(filepath.Join(dir, "stdout.log"))
		if err != nil {
			return err
		}
		defer stdout.Close()

		stderr, err := os.Create(filepath.Join(dir, "stderr.log"))
		if err != nil {
			return err
		}
		defer stderr.Close()

		reexec := exec.Command(os.Args[0], os.Args[1:]...)
		reexec.Env = append(os.Environ(), "RTR7_SAFE_UPDATE_REEXEC="+buildTimestamp)
		reexec.Stderr = io.MultiWriter(stderr, os.Stderr)
		reexec.Stdout = io.MultiWriter(stdout, os.Stdout)
		return reexec.Run()
	}

	log.Printf("flags are set to:")
	log.Printf("-updates_dir=%q", *updatesDir)

	log.Printf("verifying healthiness")

	if err := verifyHealthy(); err != nil {
		return err
	}

	log.Printf("router healthy, proceeding with update")

	latest, err := latestImage()
	if err != nil {
		log.Printf("rollback will not be possible: %v", err)
	} else {
		log.Printf("latest image: %v", latest)
	}

	// TODO(later): print a warning if the router is running a different image
	// (detect by requesting and comparing a checksum)

	if err := storeBackup(dir); err != nil {
		return err
	}

	log.Printf("building images using %s", *buildCommand)
	if err := buildImage(dir); err != nil {
		return err
	}

	log.Printf("updating")
	if err := update(dir); err != nil {
		return err
	}

	// wait 1 second until gokrazy decides to reboot, another second for the
	// device to definitely stop responding to health queries.
	time.Sleep(2 * time.Second)

	log.Printf("awaiting healthiness")
	start := time.Now()
	for time.Since(start) < 2*time.Minute {
		if err := verifyHealthy(); err != nil {
			log.Printf("unhealthy after %v: %v", time.Since(start), err)
		} else {
			log.Printf("became healthy after %v", time.Since(start))
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err := verifyHealthy(); err != nil {
		return rollback(latest)
	}

	recoverFn := filepath.Join(dir, "recover.bash")
	recoverScript := fmt.Sprintf(`#!/bin/bash
GOPATH=$(go env GOPATH) sudo --preserve-env=GOPATH $(which rtr7-recover) -boot=boot.img -root=root.img -mbr=mbr.img
`)
	if err := ioutil.WriteFile(recoverFn, []byte(recoverScript), 0755); err != nil {
		return err
	}
	log.Printf("recovery script stored in %s", recoverFn)

	if err := keepOnly(*keepOnlyN); err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
