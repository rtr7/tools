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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/gokrazy/tools/packer"
	"golang.org/x/sys/unix"
)

func deviceSize(fd uintptr) (uint64, error) {
	var devsize uint64
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&devsize))); errno != 0 {
		return 0, fmt.Errorf("BLKGETSIZE64: %v", errno)
	}
	return devsize, nil
}

func partition(path string) error {
	o, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer o.Close()

	devsize, err := deviceSize(uintptr(o.Fd()))
	if err != nil {
		return err
	}
	log.Printf("device holds %d bytes", devsize)

	hostname := kernelParameter("rtr7.hostname")
	p := packer.NewPackForHost(hostname)
	if err := p.Partition(o, devsize); err != nil {
		return err
	}

	return p.RereadPartitions(o)
}

func download(target, url string) error {
	f, err := os.OpenFile(target, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		return fmt.Errorf("unexpected HTTP status code: got %d, want %d", got, want)
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

func kernelParameter(param string) string {
	cmdline, err := ioutil.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}

	parts := strings.Split(strings.TrimSpace(string(cmdline)), " ")
	for _, part := range parts {
		if strings.HasPrefix(part, param+"=") {
			return strings.TrimPrefix(part, param+"=")
		}
	}
	return ""
}

// see github.com/rtr7/router7/internal/netconfig.InterfaceDetails
type InterfaceDetails struct {
	HardwareAddr      string `json:"hardware_addr"`       // e.g. dc:9b:9c:ee:72:fd
	SpoofHardwareAddr string `json:"spoof_hardware_addr"` // e.g. dc:9b:9c:ee:72:fd
	Name              string `json:"name"`                // e.g. uplink0, or lan0
	Addr              string `json:"addr"`                // e.g. 192.168.42.1/24
}

// see github.com/rtr7/router7/internal/netconfig.InterfaceConfig
type InterfaceConfig struct {
	Interfaces []InterfaceDetails `json:"interfaces"`
}

// Partition returns the file system path identifying the specified partition on
// the root device from which gokrazy was booted.
//
// E.g. Partition(2) = /dev/mmcblk0p2
func partitionPath(dev string, number int) string {
	if (strings.HasPrefix(dev, "/dev/mmcblk") ||
		strings.HasPrefix(dev, "/dev/loop") ||
		strings.HasPrefix(dev, "/dev/nvme")) &&
		!strings.HasSuffix(dev, "p") {
		dev += "p"
	}
	return dev + strconv.Itoa(number)
}

func writeInterfacesJSON(fn string) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue // skip loopback interface(s)
		}
		if iface.Flags&net.FlagUp == 0 {
			continue // skip interfaces which are down
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		if len(addrs) == 0 {
			continue
		}
		cfg := InterfaceConfig{
			Interfaces: []InterfaceDetails{
				{
					HardwareAddr: iface.HardwareAddr.String(),
					Name:         "lan0",
					Addr:         addrs[0].String(),
				},
			},
		}
		b, err := json.Marshal(&cfg)
		if err != nil {
			return err
		}
		return ioutil.WriteFile(fn, b, 0644)
	}
	return err
}

func logic() error {
	// /proc is useful for exposing process details and for
	// interactive debugging sessions.
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		if sce, ok := err.(syscall.Errno); ok && sce == syscall.EBUSY {
			// /proc was already mounted (common in setups using nfsroot= or initramfs)
		} else {
			return fmt.Errorf("proc: %v", err)
		}
	}

	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, ""); err != nil {
		if sce, ok := err.(syscall.Errno); ok && sce == syscall.EBUSY {
			// /dev was already mounted (common in setups using nfsroot= or initramfs)
		} else {
			return fmt.Errorf("devtmpfs: %v", err)
		}
	}

	server := kernelParameter("rtr7.server")
	if server == "" {
		log.Fatalf("Could not extract rtr7.server= from kernel command line")
	}

	blockDev := "/dev/sda"
	if _, err := os.Stat(blockDev); err != nil {
		blockDev = "/dev/nvme0n1"
	}
	log.Printf("partitioning %s", blockDev)

	if err := partition(blockDev); err != nil {
		return err
	}

	for _, part := range []struct {
		target string
		url    string
	}{
		{blockDev, "http://" + server + ":7773/mbr.img"},
		{partitionPath(blockDev, 1), "http://" + server + ":7773/boot.img"},
		{partitionPath(blockDev, 2), "http://" + server + ":7773/root.img"},
	} {
		log.Printf("downloading %s to %s", part.url, part.target)
		if err := download(part.target, part.url); err != nil {
			return err
		}
	}

	perm := partitionPath(blockDev, 4)

	if err := syscall.Mount(perm, "/perm", "ext4", 0, ""); err != nil {
		log.Printf("Could not mount permanent storage partition: %v", err)
		log.Printf("creating ext4 file system on %s", perm)

		mke2fs := exec.Command("/mke2fs", "-t", "ext4", perm)
		mke2fs.Stdout = os.Stdout
		mke2fs.Stderr = os.Stderr
		if err := mke2fs.Run(); err != nil {
			return err
		}

		if err := syscall.Mount(perm, "/perm", "ext4", 0, ""); err != nil {
			return fmt.Errorf("Could not mount permanent storage partition: %v", err)
		}
	}

	resp, err := http.Get("http://" + server + ":7773/backup.tar.gz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		// no backup flag specified
		log.Printf("not restoring a backup: no -backup flag specified")
	case http.StatusOK:
		if err := restore("/perm", resp.Body); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unexpected HTTP status code %v", resp.StatusCode)
	}

	if _, err := os.Stat("/perm/interfaces.json"); err != nil {
		if err := writeInterfacesJSON("/perm/interfaces.json"); err != nil {
			return err
		}
	}

	if err := syscall.Unmount("/perm", 0); err != nil {
		return fmt.Errorf("Could not unmount permanent storage partition: %v", err)
	}

	log.Printf("communicating success to rt7-recover")
	http.Post("http://"+server+":7773/success", "", nil)

	log.Printf("rebooting")

	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART); err != nil {
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
