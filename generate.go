package main

//go:generate /bin/sh -c "go run goembed.go -gzip -package e2fsprogs -var Bundled third_party/e2fsprogs-1.44.2/* > internal/e2fsprogs/GENERATED_e2fsprogs.go"
//go:generate /bin/sh -c "go run goembed.go -gzip -package pxelinux -var Bundled third_party/pxelinux-6.03/* > internal/pxelinux/GENERATED_pxelinux.go"
