package main

//go:generate /bin/sh -c "go run goembed.go -gzip -package e2fsprogs -var Bundled third_party/e2fsprogs-1.44.2/* > internal/e2fsprogs/GENERATED_e2fsprogs.go"
