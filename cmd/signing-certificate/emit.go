// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// emit writes the octets, and nothing else: no trailing newline, since the contract signs the
// exact octets. It is reached only after signingcert.Encode has succeeded, so nothing is
// written on any refusal.
//
// With --out the file is created exclusively (O_EXCL): an existing file is refused and left
// untouched, and any failure after the create removes the file this call created, so no partial
// certificate is left. That removal path has no cheap in-process trigger; it is argued here, not
// tested. Not a temporary file and a hard link: the certificate leaves on removable media,
// commonly FAT or exFAT, which have no hard links, and a rename would overwrite. It branches on
// whether --out was set, not on its value, so --out= is an error, never stdout.
func emit(octets []byte, in inputs, stdout io.Writer) error {
	if !in.outSet {
		n, err := stdout.Write(octets)
		if err == nil && n != len(octets) {
			err = io.ErrShortWrite
		}
		return err
	}

	f, err := os.OpenFile(in.out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return errOutExists
	}
	if err != nil {
		return err
	}
	_, werr := f.Write(octets)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(in.out)
		return err
	}
	return nil
}
