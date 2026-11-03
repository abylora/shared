// SPDX-License-Identifier: AGPL-3.0-only

package keysetvectors

import (
	"embed"
	"encoding/json"
	"io/fs"
	"strconv"
	"strings"
)

//go:embed *.json
var files embed.FS

// FS returns the vector files, every *.json of this directory at the root of the returned file
// system. SCHEMA.md, beside them in the repository, is their format.
func FS() fs.FS { return files }

// Load decodes every vector file. Every call decodes afresh, so a caller may change what it
// gets back.
func Load() (Vectors, error) { return load(files) }

// LoadFile decodes the one vector file name, for example "consumer-01-empty-snapshot.json".
func LoadFile(name string) (Vectors, error) { return loadFile(files, name) }

func load(fsys fs.FS) (Vectors, error) {
	names, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return Vectors{}, &LoadError{Err: err}
	}
	if len(names) == 0 {
		return Vectors{}, &LoadError{Err: ErrNoFiles}
	}

	var all Vectors
	owner := map[string]string{}
	for _, name := range names {
		v, err := loadFile(fsys, name)
		if err != nil {
			return Vectors{}, err
		}
		for _, id := range v.ids() {
			if _, dup := owner[id]; dup {
				return Vectors{}, &LoadError{File: name, Case: id, Err: ErrCaseIDRepeated}
			}
			owner[id] = name
		}
		all.Consumer = append(all.Consumer, v.Consumer...)
		all.Conformance = append(all.Conformance, v.Conformance...)
		all.Resume = append(all.Resume, v.Resume...)
		all.NodeDirection = append(all.NodeDirection, v.NodeDirection...)
	}

	return all, nil
}

func loadFile(fsys fs.FS, name string) (Vectors, error) {
	group, number, ok := fileNumber(name)
	if !ok {
		return Vectors{}, &LoadError{File: name, Err: ErrFileName}
	}
	octets, err := fs.ReadFile(fsys, name)
	if err != nil {
		return Vectors{}, &LoadError{File: name, Err: err}
	}
	if err := refuseDuplicateKeys(octets); err != nil {
		return Vectors{}, &LoadError{File: name, Err: err}
	}

	var f struct {
		Schema *string           `json:"schema"`
		Kind   *Kind             `json:"kind"`
		Rules  []string          `json:"rules"`
		Cases  []json.RawMessage `json:"cases"`
	}
	if err := strict(octets, &f); err != nil {
		return Vectors{}, &LoadError{File: name, Err: err}
	}
	switch {
	case f.Schema == nil || f.Kind == nil || len(f.Rules) == 0:
		return Vectors{}, &LoadError{File: name, Err: ErrFieldMissing}
	case *f.Schema != Schema:
		return Vectors{}, &LoadError{File: name, Err: ErrSchema}
	case !knownKinds[*f.Kind]:
		return Vectors{}, &LoadError{File: name, Err: ErrKindUnknown}
	case (group == "consumer") != (*f.Kind == KindConsumer):
		return Vectors{}, &LoadError{File: name, Err: ErrFileName}
	case len(f.Cases) == 0:
		return Vectors{}, &LoadError{File: name, Err: ErrNoCases}
	}

	var v Vectors
	seen := map[string]bool{}
	for i, raw := range f.Cases {
		id := peekID(raw, i)
		if err := decodeCase(&v, *f.Kind, name, raw); err != nil {
			return Vectors{}, &LoadError{File: name, Case: id, Err: err}
		}
		if !strings.HasPrefix(id, number+"-") {
			return Vectors{}, &LoadError{File: name, Case: id, Err: ErrCaseIDPrefix}
		}
		if seen[id] {
			return Vectors{}, &LoadError{File: name, Case: id, Err: ErrCaseIDRepeated}
		}
		seen[id] = true
	}

	return v, nil
}

// fileNumber splits "consumer-07-malformed-entry.json" into "consumer" and "07".
func fileNumber(name string) (group, number string, ok bool) {
	parts := strings.SplitN(strings.TrimSuffix(name, ".json"), "-", 3)
	if len(parts) != 3 || (parts[0] != "consumer" && parts[0] != "producer") || parts[1] == "" {
		return "", "", false
	}

	return parts[0], parts[1], true
}

// peekID reads a case's id for an error report, before the case is known to be valid.
func peekID(raw json.RawMessage, index int) string {
	var c struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &c) != nil || c.ID == "" {
		return "case " + strconv.Itoa(index)
	}

	return c.ID
}

// decodeCase decodes one case of a file of the given kind into v.
func decodeCase(v *Vectors, kind Kind, file string, raw json.RawMessage) error {
	switch kind {
	case KindConsumer:
		c, err := decodeConsumerCase(raw)
		if err != nil {
			return err
		}
		c.File = file
		v.Consumer = append(v.Consumer, c)
	case KindConformance:
		c, err := decodeConformanceCase(raw)
		if err != nil {
			return err
		}
		c.File = file
		v.Conformance = append(v.Conformance, c)
	case KindResume:
		c, err := decodeResumeCase(raw)
		if err != nil {
			return err
		}
		c.File = file
		v.Resume = append(v.Resume, c)
	case KindNodeDirection:
		c, err := decodeNodeDirectionCase(raw)
		if err != nil {
			return err
		}
		c.File = file
		v.NodeDirection = append(v.NodeDirection, c)
	default:
		return ErrKindUnknown
	}

	return nil
}
