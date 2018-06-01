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
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/krolaw/dhcp4"
	"github.com/krolaw/dhcp4/conn"
	"github.com/pin/tftp"
)

// TODO: enable automatic reboot, otherwise transient errors leave the box hanging
const pxeLinuxConfig = `DEFAULT recover

LABEL recover
LINUX vmlinuz
APPEND initrd=initrd rootfstype=ramfs ip=dhcp rdinit=/rt7-recovery-init console=ttyS0,115200n8`

var mux = map[string]func(io.ReaderFrom) error{
	"lpxelinux.0":          serveFile("/usr/lib/PXELINUX/lpxelinux.0"),
	"ldlinux.c32":          serveFile("/usr/lib/syslinux/modules/bios/ldlinux.c32"),
	"pxelinux.cfg/default": serveConst(pxeLinuxConfig),
	"vmlinuz":              serveFile("/home/michael/router7/tftpboot/vmlinuz"),
	"initrd":               serveInitrd(),
}

func serveInitrd() func(io.ReaderFrom) error {
	return func(rf io.ReaderFrom) error {
		// TODO: create cpio archive in Go
		var buf bytes.Buffer
		cpio := exec.Command("cpio", "-H", "newc", "-o", "--quiet")
		cpio.Stderr = os.Stderr
		cpio.Stdout = &buf
		cpio.Stdin = strings.NewReader(strings.Join([]string{
			"dumpe2fs",
			"mke2fs",
			"perm",
			"rt7-recovery-init", // TODO: compile on startup
		}, "\n"))
		cpio.Dir = "/home/michael/router7/tftpboot/initrd.unpacked"
		if err := cpio.Run(); err != nil {
			return err
		}
		rf.(tftp.OutgoingTransfer).SetSize(int64(buf.Len()))
		_, err := rf.ReadFrom(&buf)
		return err
	}
}

func serveConst(contents string) func(io.ReaderFrom) error {
	return func(rf io.ReaderFrom) error {
		rf.(tftp.OutgoingTransfer).SetSize(int64(len(contents)))
		_, err := rf.ReadFrom(strings.NewReader(contents))
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
}

func (h *dhcpHandler) ServeDHCP(p dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) dhcp4.Packet {
	log.Printf("got DHCP packet: %+v, msgType: %v, options: %v", p, msgType, options)
	serverIP := net.IP{10, 0, 0, 76} // TODO: set based on incoming network IF

	if msgType != dhcp4.Discover &&
		!net.IP(options[dhcp4.OptionServerIdentifier]).Equal(serverIP) {
		return nil // message not for this dhcp server
	}

	// TODO: check for PXEClient option?

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
	// TODO: serve bootloader from syslinux location

	// HTTP performs significantly better than TFTP for larger files (reduces
	// recovery time from minutes to seconds).
	http.Handle("/", http.FileServer(http.Dir("/tmp/recovery")))
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

	return eg.Wait()
}

func main() {
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
