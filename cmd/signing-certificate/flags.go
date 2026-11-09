// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"time"
)

// inputs is the command line, parsed: text, not yet judged.
type inputs struct {
	signingPublicKey string
	rootPublicKey    string
	env              string
	notBefore        string
	notAfter         string
	out              string
	outSet           bool
}

// onceString is a flag with no default that records whether it was set, and refuses a second
// value: flag.FlagSet would otherwise keep the last one silently, and --env staging --env prod
// would sign prod.
type onceString struct {
	value string
	set   bool
}

func (o *onceString) String() string { return o.value }

func (o *onceString) Set(s string) error {
	if o.set {
		return errFlagRepeated
	}
	o.value, o.set = s, true
	return nil
}

// parseFlags reads the command line. Five flags are required and have no default; --out is the
// only optional one. It judges nothing but the command line itself.
func parseFlags(args []string) (inputs, error) {
	fs := flag.NewFlagSet("signing-certificate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var signing, root, env, notBefore, notAfter, out onceString
	fs.Var(&signing, "signing-public-key", "")
	fs.Var(&root, "root-public-key", "")
	fs.Var(&env, "env", "")
	fs.Var(&notBefore, "not-before", "")
	fs.Var(&notAfter, "not-after", "")
	fs.Var(&out, "out", "")

	if err := fs.Parse(args); err != nil {
		return inputs{}, err
	}
	if fs.NArg() != 0 {
		return inputs{}, errArgument
	}
	for _, r := range []struct {
		name string
		v    *onceString
	}{
		{"signing-public-key", &signing}, {"root-public-key", &root}, {"env", &env},
		{"not-before", &notBefore}, {"not-after", &notAfter},
	} {
		if !r.v.set {
			return inputs{}, fmt.Errorf("--%s is required", r.name)
		}
	}

	return inputs{
		signingPublicKey: signing.value, rootPublicKey: root.value, env: env.value,
		notBefore: notBefore.value, notAfter: notAfter.value, out: out.value, outSet: out.set,
	}, nil
}

// parseInstant reads a timestamp flag. It accepts the text only if it is the one spelling
// time.RFC3339 gives that instant in UTC -- exactly YYYY-MM-DDTHH:MM:SSZ -- so the text the
// operator typed is the text the root signs: an offset, a fraction, a lowercase t or z, or a
// one-digit hour is refused, never converted. This is the flag's syntax, not a certificate rule:
// whether an instant is encodable and whether the window is empty are signingcert.Encode's to
// refuse, and this command never compares the two instants.
func parseInstant(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.UTC().Format(time.RFC3339) != s {
		return time.Time{}, errInstantSyntax
	}
	return t.UTC(), nil
}
