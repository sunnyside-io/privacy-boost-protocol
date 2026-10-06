package addressprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// ReadManifest reads a manifest of at most 1 MiB, rejects unknown JSON fields
// and trailing data, and validates its deployment and artifact metadata.
func ReadManifest(path string) (Manifest, error) {
	var manifest Manifest
	f, err := os.Open(path)
	if err != nil {
		return manifest, err
	}

	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return manifest, err
	}
	return DecodeManifest(data)
}

// DecodeManifest validates the exact bytes authenticated by a deployment policy.
// Its bounded, strict decoder is shared with mounted-file manifest loading.
func DecodeManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	if len(data) > 1<<20 {
		return manifest, errors.New("address manifest exceeds size limit")
	}

	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&manifest); err != nil {
		return manifest, err
	}

	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return manifest, errors.New("trailing address manifest data")
	}

	return manifest, manifest.Validate()
}
