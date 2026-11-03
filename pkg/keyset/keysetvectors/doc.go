// SPDX-License-Identifier: AGPL-3.0-only

// Package keysetvectors is the key set stream's test vectors (key-set.md, the vectors
// paragraph), shipped as data: JSON files beside this one, embedded and exported through FS so
// that another module's tests can load them, and strict typed loaders that return keysetpb
// messages. The format is SCHEMA.md in this directory, written so that a consumer in any
// language can read the files without this package.
//
// TWO KINDS. Consumer vectors (kind "consumer") are messages to the resulting cursor, set,
// Applied reports, skipped gauge and violations; a consumer passes them. Producer vectors are
// conformance ("producer.conformance": old set, new set and an emitted Delta, judged), resume
// ("producer.resume": held version, change log and published version to a snapshot or deltas) and
// the node's direction ("producer.node_direction", rule 16); a producer passes them.
//
// THE EXPECTATIONS COME FROM THE CONTRACT. Every expected value was derived by hand from
// key-set.md, never copied from an implementation's output. pkg/keyset, the reference, runs
// every file in its own tests.
//
// NO VERSION IS 1 (rule 9: the counter is seeded at a random value of at least 1). Every case
// uses a non-trivial base version, so an implementation that assumes the first version is 1
// fails. vectors_test.go holds that.
//
// A DATA PACKAGE. It never imports pkg/keyset, so no vector is shaped by the reference's types,
// and pkg/keyset never imports it, so importing the reference embeds no vector. Nothing here
// imports testing.
package keysetvectors
