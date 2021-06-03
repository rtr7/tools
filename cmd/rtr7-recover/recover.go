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
	bootPath     = flag.String("boot", "", "Path to gokr-packer’s -overwrite_boot")
	rootPath     = flag.String("root", "", "Path to gokr-packer’s -overwrite_root")
	mbrPath      = flag.String("mbr", "", "Path to gokr-packer’s -overwrite_mbr")
	backupPath   = flag.String("backup", "", "Path to a backup.tar.gz archive from backupd")
	reset        = flag.Bool("reset", true, "Trigger a reset if a Teensy rebootor is attached")
	ifname       = flag.String("interface", firstIfname(), "ethernet interface name (e.g. enp0s31f6) on which to serve TFTP, HTTP, DHCP")
	recoverOctet = flag.Int("recover_octet", 1, "last octet of the IP address to use during recovery. E.g., if -interface uses address 10.0.0.76, -recover_octet=1 results in 10.0.0.1 being handed out to the client")
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

type dhcpHandler struct {
	serverIP  net.IP
	recoverIP net.IP
	options   dhcp4.Options
	// ServeDHCP responds to requests with Vendor class identifier “PXEClient”,
	// stores the requester’s MAC address in lastHWAddr and allows subsequent
	// requests (from the recovery Linux) from that same address.
	lastHWAddr net.HardwareAddr
}

func (h *dhcpHandler) ServeDHCP(p dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) dhcp4.Packet {
	prefix := fmt.Sprintf("[dhcp] %v DHCP%v → ", p.CHAddr(), strings.ToUpper(msgType.String()))
	if msgType != dhcp4.Discover &&
		!net.IP(options[dhcp4.OptionServerIdentifier]).Equal(h.serverIP) {
		log.Printf(prefix+"ignore (for other server %v)", options[dhcp4.OptionServerIdentifier])
		return nil
	}

	if h.lastHWAddr != nil {
		if got, want := p.CHAddr(), h.lastHWAddr; !bytes.Equal(got, want) {
			log.Printf(prefix+"DHCPNAK (%v is the first PXE client)", want)
			return dhcp4.ReplyPacket(p, dhcp4.NAK, h.serverIP, nil, 0, nil)
		}
	} else {
		if !bytes.HasPrefix(options[dhcp4.OptionVendorClassIdentifier], []byte("PXEClient")) {
			log.Printf(prefix + "ignore (PXEClient vendor class option not found)")
			return nil
		}
	}
	switch msgType {
	case dhcp4.Discover:
		log.Printf(prefix + "DHCPOFFER")
		rp := dhcp4.ReplyPacket(p,
			dhcp4.Offer,
			h.serverIP,
			h.recoverIP,
			2*time.Hour,
			h.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
		return rp

	case dhcp4.Request:
		log.Printf(prefix + "DHCPACK")
		h.lastHWAddr = p.CHAddr()
		rp := dhcp4.ReplyPacket(p,
			dhcp4.ACK,
			h.serverIP,
			h.recoverIP,
			2*time.Hour,
			h.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
		rp.SetSIAddr(h.serverIP)         // next server
		rp.SetFile([]byte("pxelinux.0")) // boot file name
		return rp

	default:
		log.Printf(prefix+"ignore (unsupported message type %v)", msgType)
	}
	return nil
}

func findServerIP() (net.IP, error) {
	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var candidates []net.IP
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.To4() == nil {
			continue // skip non-IPv4
		}
		candidates = append(candidates, ipnet.IP)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no IPv4 address found on interface %s", *ifname)
	}
	if len(candidates) > 1 {
		return nil, fmt.Errorf("more than one IPv4 address found on interface %s: %v", *ifname, candidates)
	}
	return candidates[0].To4(), nil
}

func logic() error {
	serverIP, err := findServerIP()
	if err != nil {
		return err
	}

	recoverIP := make(net.IP, 4)
	copy(recoverIP, serverIP.To4())
	recoverIP[3] = byte(*recoverOctet)
	log.Printf("client will use IP address %v during recovery", recoverIP)

	pxeLinuxConfig := fmt.Sprintf(`DEFAULT recover

LABEL recover
LINUX vmlinuz
APPEND initrd=initrd rootfstype=ramfs ip=dhcp rdinit=/rtr7-recovery-init console=ttyS0,115200n8 panic=10 panic_on_oops=1 rtr7.server=%s`, serverIP)

	mux := map[string]func(io.ReaderFrom) error{
		"pxelinux.cfg/default": serveConst([]byte(pxeLinuxConfig)),
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

	var eg errgroup.Group

	// HTTP performs significantly better than TFTP for larger files (reduces
	// recovery time from minutes to seconds).
	fileHandler := func(path string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if path == "" {
				log.Printf("[http] %s %s 404", r.URL.Path, r.RemoteAddr)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			log.Printf("[http] %s %s", r.URL.Path, r.RemoteAddr)
			http.ServeFile(w, r, path)
		}
	}
	http.HandleFunc("/boot.img", fileHandler(*bootPath))
	http.HandleFunc("/root.img", fileHandler(*rootPath))
	http.HandleFunc("/mbr.img", fileHandler(*mbrPath))
	http.HandleFunc("/backup.tar.gz", fileHandler(*backupPath))
	http.HandleFunc("/success", func(_ http.ResponseWriter, r *http.Request) {
		log.Printf("[http] %s %s", r.URL.Path, r.RemoteAddr)
		os.Exit(0)
	})
	eg.Go(func() error { return http.ListenAndServe(":7773", nil) })

	readHandler := func(filename string, rf io.ReaderFrom) (err error) {
		defer func() {
			result := "success"
			if err != nil {
				result = err.Error()
			}
			log.Printf("[tftp] %s: %v", filename, result)
		}()
		handler, ok := mux[filename]
		if !ok {
			return fmt.Errorf("file not found")
		}
		return handler(rf)
	}
	tsrv := tftp.NewServer(readHandler, nil)
	eg.Go(func() error { return tsrv.ListenAndServe(":69") })

	handler := &dhcpHandler{
		serverIP:  serverIP,
		recoverIP: recoverIP,
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

	cn4011, err := conn.NewUDP4BoundListener(*ifname, ":4011")
	if err != nil {
		return fmt.Errorf("NewUDP4BoundListener(%q, %q): %v", *ifname, ":67", err)
	}
	eg.Go(func() error { return dhcp4.Serve(cn4011, handler) })

	if *reset {
		if err := teensyReset(); err != nil {
			log.Printf("teensy rebootor-triggered reset failed (%v), please reset the apu2c4 manually", err)
		}
	}

	log.Printf("serving TFTP, HTTP, DHCP (for PXE clients) on %s (%s)", serverIP, *ifname)

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

	if *bootPath == "" || *rootPath == "" || *mbrPath == "" {
		log.Fatalf("-boot, -mbr and -root must be specified")
	}

	if _, err := os.Stat(*bootPath); err != nil {
		log.Fatalf("-boot: %v", err)
	}

	if _, err := os.Stat(*rootPath); err != nil {
		log.Fatalf("-root: %v", err)
	}

	if _, err := os.Stat(*mbrPath); err != nil {
		log.Fatalf("-mbr: %v", err)
	}

	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
