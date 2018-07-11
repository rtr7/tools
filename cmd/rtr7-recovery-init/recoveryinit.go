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
	"encoding/binary"
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
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TODO: come up with a good way to keep this in sync with gokrazy

const MB = 1024 * 1024

var (
	active   = byte(0x80)
	inactive = byte(0x00)

	// invalidCHS results in using the sector values instead
	invalidCHS = [3]byte{0xFE, 0xFF, 0xFF}

	FAT   = byte(0xc)
	Linux = byte(0x83)

	signature = uint16(0xAA55)
)

func writePartitionTable(w io.Writer, devsize uint64) error {
	for _, v := range []interface{}{
		[446]byte{}, // boot code

		// partition 1
		active,
		invalidCHS,
		FAT,
		invalidCHS,
		uint32(8192),           // start at 8192 sectors
		uint32(100 * MB / 512), // 100MB in size

		// partition 2
		inactive,
		invalidCHS,
		FAT,
		invalidCHS,
		uint32(8192 + (100 * MB / 512)), // start after partition 1
		uint32(500 * MB / 512),          // 500MB in size

		// partition 3
		inactive,
		invalidCHS,
		FAT,
		invalidCHS,
		uint32(8192 + (600 * MB / 512)), // start after partition 2
		uint32(500 * MB / 512),          // 500MB in size

		// partition 3
		inactive,
		invalidCHS,
		Linux,
		invalidCHS,
		uint32(8192 + (1100 * MB / 512)),                   // start after partition 3
		uint32((devsize / 512) - 8192 - (1100 * MB / 512)), // remainder

		signature,
	} {
		if err := binary.Write(w, binary.LittleEndian, v); err != nil {
			return err
		}
	}

	return nil
}

func deviceSize(fd uintptr) (uint64, error) {
	var devsize uint64
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&devsize))); errno != 0 {
		return 0, fmt.Errorf("BLKGETSIZE64: %v", errno)
	}
	return devsize, nil
}

func rereadPartitions(fd uintptr) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.BLKRRPART, 0); errno != 0 {
		return fmt.Errorf("re-read partition table: %v", errno)
	}
	return nil
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

	if err := writePartitionTable(o, devsize); err != nil {
		return err
	}

	// Make Linux re-read the partition table. Sequence of system calls like in fdisk(8).
	unix.Sync()

	if err := rereadPartitions(uintptr(o.Fd())); err != nil {
		return err
	}

	if err := o.Sync(); err != nil {
		return err
	}

	if err := o.Close(); err != nil {
		return err
	}

	unix.Sync()
	return nil
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

	log.Printf("partitioning /dev/sda")

	if err := partition("/dev/sda"); err != nil {
		return err
	}

	for _, part := range []struct {
		target string
		url    string
	}{
		{"/dev/sda", "http://" + server + ":7773/mbr.img"},
		{"/dev/sda1", "http://" + server + ":7773/boot.img"},
		{"/dev/sda2", "http://" + server + ":7773/root.img"},
	} {
		log.Printf("downloading %s to %s", part.url, part.target)
		if err := download(part.target, part.url); err != nil {
			return err
		}
	}

	dumpe2fs := exec.Command("/dumpe2fs", "-h", "/dev/sda4")
	if err := dumpe2fs.Run(); err != nil {
		log.Printf("creating ext4 file system on /dev/sda4")

		mke2fs := exec.Command("/mke2fs", "-t", "ext4", "/dev/sda4")
		mke2fs.Stdout = os.Stdout
		mke2fs.Stderr = os.Stderr
		if err := mke2fs.Run(); err != nil {
			return err
		}
	}

	if err := syscall.Mount("/dev/sda4", "/perm", "ext4", 0, ""); err != nil {
		return fmt.Errorf("Could not mount permanent storage partition: %v", err)
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
