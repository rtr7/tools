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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sync/errgroup"

	cpio "github.com/cavaliercoder/go-cpio"
	"github.com/google/gousb"
	"github.com/krolaw/dhcp4"
	"github.com/krolaw/dhcp4/conn"
	"github.com/pin/tftp"
	"github.com/rtr7/tools/internal/e2fsprogs"
)

var (
	bootPath = flag.String("boot", "", "Path to gokr-apu-packer’s -overwrite_boot")
	rootPath = flag.String("root", "", "Path to gokr-apu-packer’s -overwrite_root")
	reset    = flag.Bool("reset", true, "Trigger a reset if a Teensy rebootor is attached")
)

// TODO: enable automatic reboot, otherwise transient errors leave the box hanging
const pxeLinuxConfig = `DEFAULT recover

LABEL recover
LINUX vmlinuz
APPEND initrd=initrd rootfstype=ramfs ip=dhcp rdinit=/rtr7-recovery-init console=ttyS0,115200n8`

var mux = map[string]func(io.ReaderFrom) error{
	"lpxelinux.0":          serveFile("/usr/lib/PXELINUX/lpxelinux.0"),
	"ldlinux.c32":          serveFile("/usr/lib/syslinux/modules/bios/ldlinux.c32"),
	"pxelinux.cfg/default": serveConst([]byte(pxeLinuxConfig)),
	"vmlinuz":              serveFile("/home/michael/router7/tftpboot/vmlinuz"),
}

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
	log.Printf("hdr = %+v", hdr)
	if err := w.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.Copy(w, f); err != nil {
		return err
	}

	return err
}

func serveConst(contents []byte) func(io.ReaderFrom) error {
	return func(rf io.ReaderFrom) error {
		rf.(tftp.OutgoingTransfer).SetSize(int64(len(contents)))
		_, err := rf.ReadFrom(bytes.NewReader(contents))
		return err
	}
}

func serveFile(filename string) func(io.ReaderFrom) error {
	return func(rf io.ReaderFrom) error {
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = rf.ReadFrom(f)
		return err
	}
}

func readHandler(filename string, rf io.ReaderFrom) (err error) {
	defer func() {
		result := "success"
		if err != nil {
			result = err.Error()
		}
		log.Printf("[tftp] read %q: %v", filename, result)
	}()
	handler, ok := mux[filename]
	if !ok {
		return fmt.Errorf("file not found")
	}
	return handler(rf)
}

type dhcpHandler struct {
	options dhcp4.Options
	// ServeDHCP responds to requests with Vendor class identifier “PXEClient”,
	// stores the requester’s MAC address in lastHWAddr and allows subsequent
	// requests (from the recovery Linux) from that same address.
	lastHWAddr net.HardwareAddr
}

func (h *dhcpHandler) ServeDHCP(p dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) dhcp4.Packet {
	// TODO: remove after debugging:
	log.Printf("got DHCP packet: %+v, msgType: %v, options: %v", p, msgType, options)
	serverIP := net.IP{10, 0, 0, 76} // TODO: set based on incoming network IF

	if msgType != dhcp4.Discover &&
		!net.IP(options[dhcp4.OptionServerIdentifier]).Equal(serverIP) {
		return nil // message not for this dhcp server
	}

	if !bytes.HasPrefix(options[dhcp4.OptionVendorClassIdentifier], []byte("PXEClient")) &&
		!bytes.Equal(h.lastHWAddr, p.CHAddr()) {
		return nil // skip non-PXE requests
	}

	switch msgType {
	case dhcp4.Discover:
		rp := dhcp4.ReplyPacket(p,
			dhcp4.Offer,
			serverIP,
			net.IP{10, 0, 0, 92},
			2*time.Hour,
			h.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
		return rp

	case dhcp4.Request:
		h.lastHWAddr = p.CHAddr()
		rp := dhcp4.ReplyPacket(p,
			dhcp4.ACK,
			serverIP,
			net.IP{10, 0, 0, 92},
			2*time.Hour,
			h.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
		rp.SetSIAddr(serverIP)            // next server
		rp.SetFile([]byte("lpxelinux.0")) // boot file name
		return rp
	}
	return nil
}

func hardReboot() error {
	usb := gousb.NewContext()
	defer usb.Close()

	dev, err := usb.OpenDeviceWithVIDPID(0x16C0, 0x0477)
	if err != nil {
		return fmt.Errorf("could not open teensy rebootor: %v", err)
	}

	if err := dev.SetAutoDetach(true); err != nil {
		return err
	}

	_, done, err := dev.DefaultInterface()
	if err != nil {
		return err
	}
	defer done()

	r, err := dev.Control(
		0x21,             // bmRequestType
		9,                // bRequest
		0x0200,           // value
		0,                // index
		[]byte("reboot"), // data
	)
	if err != nil {
		return err
	}
	if got, want := r, 6; got != want {
		return fmt.Errorf("unexpected reboot reply: got %d, want %d", got, want)
	}
	return nil
}

func logic() error {
	var eg errgroup.Group

	// HTTP performs significantly better than TFTP for larger files (reduces
	// recovery time from minutes to seconds).
	fileHandler := func(path string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, path)
		}
	}
	http.HandleFunc("/boot.img", fileHandler(*bootPath))
	http.HandleFunc("/root.img", fileHandler(*rootPath))
	http.HandleFunc("/mbr.img", fileHandler("/usr/lib/syslinux/mbr/mbr.bin"))
	http.HandleFunc("/success", func(http.ResponseWriter, *http.Request) { os.Exit(0) })
	eg.Go(func() error { return http.ListenAndServe(":7773", nil) })

	tsrv := tftp.NewServer(readHandler, nil)
	eg.Go(func() error { return tsrv.ListenAndServe(":69") })

	handler := &dhcpHandler{
		options: dhcp4.Options{
			dhcp4.OptionVendorClassIdentifier: []byte("PXEClient"),
		},
	}
	cn, err := conn.NewUDP4BoundListener("enp0s31f6", ":67") // TODO: customizeable
	if err != nil {
		return err
	}
	eg.Go(func() error { return dhcp4.Serve(cn, handler) })

	if *reset {
		if err := hardReboot(); err != nil {
			log.Printf("hard reboot failed (%v), please trigger a reboot manually", err)
		}
	}

	return eg.Wait()
}

func makeInitrd() ([]byte, error) {
	tmpdir, err := ioutil.TempDir("", "rtr7-recover")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpdir)

	compile := exec.Command("go", "build", "github.com/rtr7/tools/cmd/rtr7-recovery-init")
	compile.Dir = tmpdir
	compile.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH=amd64")
	compile.Stderr = os.Stderr
	if err := compile.Run(); err != nil {
		return nil, fmt.Errorf("%v: %v", compile.Args, err)
	}

	var buf bytes.Buffer
	w := cpio.NewWriter(&buf)

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

func main() {
	flag.Parse()

	if *bootPath == "" || *rootPath == "" {
		log.Fatalf("both -boot and -root must be specified")
	}

	if _, err := os.Stat(*bootPath); err != nil {
		log.Fatalf("-boot: %v", err)
	}

	if _, err := os.Stat(*rootPath); err != nil {
		log.Fatalf("-root: %v", err)
	}

	initrd, err := makeInitrd()
	if err != nil {
		log.Fatalf("makeInitrd: %v", err)
	}
	mux["initrd"] = serveConst(initrd)

	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
