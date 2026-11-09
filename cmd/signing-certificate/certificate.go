// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"

	"github.com/abylora/shared/pkg/signingcert"
)

// certificate turns the inputs into the certificate's octets. signingcert.Encode is the ONLY
// producer of those octets, and every certificate rule -- env, weak key, self-certificate,
// encodable instants, a non-empty window -- is Encode's alone: its refusal is returned bare. What
// is checked before it is input syntax only: the timestamps' text and the key files' format.
func certificate(in inputs) ([]byte, error) {
	notBefore, err := parseInstant(in.notBefore)
	if err != nil {
		return nil, fmt.Errorf("--not-before: %w", err)
	}
	notAfter, err := parseInstant(in.notAfter)
	if err != nil {
		return nil, fmt.Errorf("--not-after: %w", err)
	}
	key, err := readPublicKeyFile(in.signingPublicKey)
	if err != nil {
		return nil, fmt.Errorf("--signing-public-key: %w", err)
	}
	root, err := readPublicKeyFile(in.rootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("--root-public-key: %w", err)
	}

	return signingcert.Encode(signingcert.Opts{
		Env:       signingcert.Env(in.env),
		Root:      signingcert.Fingerprint(root[:]),
		Key:       key,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})
}
