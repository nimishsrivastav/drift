package npm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
	"github.com/nimishsrivastav/drift/orchestrator/internal/store"
)

// newVerifier builds a check from a Subresource Integrity string and the legacy shasum.
// Following SRI, the strongest algorithm listed decides, and any one of its values may match.
// A shasum, when present, must also match. A version with neither is an error, not a pass.
func newVerifier(integrity, shasum string) (func(store.Digests) error, error) {
	wanted := map[string][][]byte{}
	for entry := range strings.FieldsSeq(integrity) {
		algorithm, value, ok := strings.Cut(entry, "-")
		if !ok {
			continue
		}
		value, _, _ = strings.Cut(value, "?") // SRI options carry nothing we use
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("decode %s integrity: %w", algorithm, err)
		}
		wanted[algorithm] = append(wanted[algorithm], decoded)
	}

	algorithm := ""
	for _, candidate := range []string{"sha512", "sha256", "sha1"} {
		if len(wanted[candidate]) > 0 {
			algorithm = candidate
			break
		}
	}

	var wantedShasum []byte
	if shasum != "" {
		decoded, err := hex.DecodeString(shasum)
		if err != nil {
			return nil, fmt.Errorf("decode shasum: %w", err)
		}
		wantedShasum = decoded
	}
	if algorithm == "" && wantedShasum == nil {
		return nil, errors.New("registry published no usable integrity hash")
	}

	return func(got store.Digests) error {
		if wantedShasum != nil && !bytes.Equal(got.SHA1, wantedShasum) {
			return fmt.Errorf("%w: shasum is %x, registry says %x", ingest.ErrIntegrity, got.SHA1, wantedShasum)
		}
		if algorithm == "" {
			return nil
		}
		var actual []byte
		switch algorithm {
		case "sha512":
			actual = got.SHA512
		case "sha256":
			actual = got.SHA256
		case "sha1":
			actual = got.SHA1
		}
		for _, value := range wanted[algorithm] {
			if bytes.Equal(actual, value) {
				return nil
			}
		}
		return fmt.Errorf("%w: %s does not match the registry's value", ingest.ErrIntegrity, algorithm)
	}, nil
}
