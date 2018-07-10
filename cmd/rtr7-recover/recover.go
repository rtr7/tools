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
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/krolaw/dhcp4"
	"github.com/krolaw/dhcp4/conn"
	"github.com/pin/tftp"
	"github.com/rtr7/tools/internal/pxelinux"
)

var (
	bootPath = flag.String("boot", "", "Path to gokr-apu-packer’s -overwrite_boot")
	rootPath = flag.String("root", "", "Path to gokr-apu-packer’s -overwrite_root")
	reset    = flag.Bool("reset", true, "Trigger a reset if a Teensy rebootor is attached")
	ifname   = flag.String("interface", firstIfname(), "ethernet interface name (e.g. enp0s31f6) on which to serve TFTP, HTTP, DHCP")
)

func firstIfname() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
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
		return iface.Name
	}
	return ""
}

const pxeLinuxConfig = `DEFAULT recover

LABEL recover
LINUX vmlinuz
APPEND initrd=initrd rootfstype=ramfs ip=dhcp rdinit=/rtr7-recovery-init console=ttyS0,115200n8 panic=10 panic_on_oops=1`

var mux = map[string]func(io.ReaderFrom) error{
	"pxelinux.cfg/default": serveConst([]byte(pxeLinuxConfig)),
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
			dhcp4.OptionSubnetMask:            []byte{255, 255, 255, 0},
		},
	}
	cn, err := conn.NewUDP4BoundListener(*ifname, ":67")
	if err != nil {
		return fmt.Errorf("NewUDP4BoundListener(%q, %q): %v", *ifname, ":67", err)
	}
	eg.Go(func() error { return dhcp4.Serve(cn, handler) })

	if *reset {
		if err := teensyReset(); err != nil {
			log.Printf("teensy rebootor-triggered reset failed (%v), please reset the apu2c4 manually", err)
		}
	}

	log.Printf("serving TFTP, HTTP, DHCP (for PXE clients)")

	return eg.Wait()
}

func packageDir(pkg string) (string, error) {
	cmd := exec.Command("go", "list", "-f", "{{ .Dir }}", pkg)
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%v: %v", cmd.Args, err)
	}
	return strings.TrimSpace(string(b)), nil
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

	kernelDir, err := packageDir("github.com/rtr7/kernel")
	if err != nil {
		log.Fatalf("could not find kernel: %v", err)
	}
	vmlinuzPath := filepath.Join(kernelDir, "vmlinuz")
	if _, err := os.Stat(vmlinuzPath); err != nil {
		log.Fatalf("could not find vmlinuz in kernel dir: %v", err)
	}
	mux["vmlinuz"] = serveFile(vmlinuzPath)

	initrd, err := makeInitrd()
	if err != nil {
		log.Fatalf("makeInitrd: %v", err)
	}
	mux["initrd"] = serveConst(initrd)

	for path, b := range pxelinux.Bundled {
		mux[filepath.Base(path)] = serveConst(b)
	}

	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
