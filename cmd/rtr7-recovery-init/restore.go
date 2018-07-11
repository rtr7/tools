package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"log"
	"os"
	"path/filepath"
)

func writeFile(dest string, hdr *tar.Header, r io.Reader) error {
	df, err := os.Create(filepath.Join(dest, hdr.Name))
	if err != nil {
		return err
	}
	defer df.Close()
	if _, err := io.Copy(df, r); err != nil {
		return err
	}
	return df.Close()
}

func restore(dest string, r io.Reader) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // end of archive
		}
		if err != nil {
			return err
		}
		log.Printf("tar entry %s", hdr.Name)
		fn := filepath.Join(dest, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeReg:
			if err := writeFile(dest, hdr, tr); err != nil {
				return err
			}
		case tar.TypeDir:
			if err := os.Mkdir(fn, os.FileMode(hdr.Mode)); err != nil {
				if !os.IsExist(err) {
					return err
				}
			}
		default:
			log.Printf("skipping tar entry with unimplemented typeflag %v", hdr.Typeflag)
			continue
		}

		if err := os.Chmod(fn, os.FileMode(hdr.Mode)); err != nil {
			return err
		}
		if err := os.Chown(fn, hdr.Uid, hdr.Gid); err != nil {
			return err
		}
		if err := os.Chtimes(fn, hdr.AccessTime, hdr.ModTime); err != nil {
			return err
		}
	}
	return nil
}
