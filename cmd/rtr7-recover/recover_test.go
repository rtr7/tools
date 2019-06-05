package main

import (
	"bytes"
	"net"
	"testing"

	"github.com/krolaw/dhcp4"
)

func messageType(p dhcp4.Packet) dhcp4.MessageType {
	opts := p.ParseOptions()
	return dhcp4.MessageType(opts[dhcp4.OptionDHCPMessageType][0])
}

func TestDHCPAddressFilter(t *testing.T) {
	// install router7 with IP address 192.0.2.1 to the next PXE booting client
	handler := &dhcpHandler{
		// 192.0.2.0/24 is TEST-NET-1 from RFC5737
		serverIP:  net.ParseIP("192.0.2.76"), // configured on local interface
		recoverIP: net.ParseIP("192.0.2.1"),  // handed to the client
		options: dhcp4.Options{
			dhcp4.OptionVendorClassIdentifier: []byte("PXEClient"),
			dhcp4.OptionSubnetMask:            []byte{255, 255, 255, 0},
		},
	}
	var macCnt byte
	mac := func() byte {
		defer func() { macCnt++ }()
		return macCnt
	}
	for _, test := range []struct {
		desc    string
		macaddr byte
		want    dhcp4.MessageType
	}{
		{
			desc:    "first MAC",
			macaddr: mac(),
			want:    dhcp4.ACK,
		},
		{
			desc:    "different MAC",
			macaddr: mac(),
			want:    dhcp4.NAK,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			p := dhcp4.RequestPacket(
				dhcp4.Request,
				net.HardwareAddr(bytes.Repeat([]byte{test.macaddr}, 6)),
				net.ParseIP("192.0.2.1"),       // requested IP address
				[]byte{0xaa, 0xbb, 0xcc, 0xdd}, // transaction ID
				false,                          // broadcast,
				[]dhcp4.Option{
					{
						Code:  dhcp4.OptionServerIdentifier,
						Value: net.IP{192, 0, 2, 76},
					},
					{
						Code:  dhcp4.OptionVendorClassIdentifier,
						Value: []byte("PXEClient"),
					},
				},
			)
			reply := handler.ServeDHCP(p, dhcp4.Request, p.ParseOptions())
			if got, want := messageType(reply), test.want; got != want {
				t.Errorf("ServeDHCP(%v) = %v, want %v", p, got, want)
			}

			// Now a non-PXE request from the same MAC address:
			p = dhcp4.RequestPacket(
				dhcp4.Request,
				net.HardwareAddr(bytes.Repeat([]byte{test.macaddr}, 6)),
				net.ParseIP("192.0.2.1"),       // requested IP address
				[]byte{0xaa, 0xbb, 0xcc, 0xdd}, // transaction ID
				false,                          // broadcast,
				[]dhcp4.Option{
					{
						Code:  dhcp4.OptionServerIdentifier,
						Value: net.IP{192, 0, 2, 76},
					},
				},
			)
			reply = handler.ServeDHCP(p, dhcp4.Request, p.ParseOptions())
			if got, want := messageType(reply), test.want; got != want {
				t.Errorf("ServeDHCP(%v) = %v, want %v", p, got, want)
			}
		})
	}

	t.Run("non-PXE request", func(t *testing.T) {
		p := dhcp4.RequestPacket(
			dhcp4.Request,
			net.HardwareAddr(bytes.Repeat([]byte{mac()}, 6)),
			net.ParseIP("192.0.2.1"),       // requested IP address
			[]byte{0xaa, 0xbb, 0xcc, 0xdd}, // transaction ID
			false,                          // broadcast,
			[]dhcp4.Option{
				{
					Code:  dhcp4.OptionServerIdentifier,
					Value: net.IP{192, 0, 2, 76},
				},
			},
		)
		reply := handler.ServeDHCP(p, dhcp4.Request, p.ParseOptions())
		if got, want := messageType(reply), dhcp4.NAK; got != want {
			t.Errorf("ServeDHCP(%v) = %v, want %v", p, got, want)
		}
	})
}
