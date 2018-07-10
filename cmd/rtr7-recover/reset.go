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
	"fmt"

	"github.com/google/gousb"
)

func teensyReset() error {
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
