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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
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

func logic() error {
	// TODO: take the target server address from a custom kernel cmdline parameter

	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, ""); err != nil {
		if sce, ok := err.(syscall.Errno); ok && sce == syscall.EBUSY {
			// /dev was already mounted (common in setups using nfsroot= or initramfs)
		} else {
			return fmt.Errorf("devtmpfs: %v", err)
		}
	}

	log.Printf("partitioning /dev/sda")

	if err := partition("/dev/sda"); err != nil {
		return err
	}

	for _, part := range []struct {
		target string
		url    string
	}{
		{"/dev/sda", "http://10.0.0.76:7773/mbr.img"},
		{"/dev/sda1", "http://10.0.0.76:7773/boot.img"},
		{"/dev/sda2", "http://10.0.0.76:7773/root.img"},
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

	// TODO: unpack an archive files for /perm
	if err := ioutil.WriteFile("/perm/interfaces.json", []byte(`{
  "interfaces": [
    {
      "hardware_addr": "00:0d:b9:49:70:18",
      "name": "uplink0"
    },
    {
      "hardware_addr": "00:0d:b9:49:70:1a",
      "name": "lan0",
      "addr": "192.168.42.1/24"
    }
  ]
}`), 0644); err != nil {
		return err
	}

	if err := syscall.Unmount("/perm", 0); err != nil {
		return fmt.Errorf("Could not unmount permanent storage partition: %v", err)
	}

	log.Printf("communicating success to rt7-recover")
	http.Post("http://10.0.0.76:7773/success", "", nil)

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