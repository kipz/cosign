//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package layout

import (
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/internal/signature"
)

const maxLayers = 1000

type sigs struct {
	v1.Image
}

var _ oci.Signatures = (*sigs)(nil)

// Get implements oci.Signatures
func (s *sigs) Get() ([]oci.Signature, error) {
	manifest, err := s.Image.Manifest()
	if err != nil {
		return nil, err
	}
	numLayers := int64(len(manifest.Layers))
	if numLayers > maxLayers {
		return nil, oci.NewMaxLayersExceeded(numLayers, maxLayers)
	}
	signatures := make([]oci.Signature, 0, numLayers)
	for _, desc := range manifest.Layers {
		l, err := s.Image.LayerByDigest(desc.Digest)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, signature.New(l, desc))
	}
	return signatures, nil
}

type oci11IntotoDSSESignatures struct {
	oci.Signatures
}

var _ oci.Signatures = (*oci11IntotoDSSESignatures)(nil)

func NewOCI11Signatures(s oci.Signatures) oci.Signatures {
	return &oci11IntotoDSSESignatures{s}
}

func (s *oci11IntotoDSSESignatures) Get() ([]oci.Signature, error) {
	sigs, err := s.Signatures.Get()
	if err != nil {
		return nil, err
	}
	manifest, err := s.Signatures.RawManifest()
	if err != nil {
		return nil, err
	}
	// unmarshall into generic map and check for ArtifactType at the top level
	var m map[string]interface{}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, err
	}
	artifactType, ok := m["artifactType"]
	if !ok {
		return nil, fmt.Errorf("no artifactType found in manifest")
	}
	if artifactType != intoto.PayloadType {
		return nil, fmt.Errorf("expected artifactType %s, got %s", intoto.PayloadType, artifactType)
	}
	result := make([]oci.Signature, 0)
	for _, sig := range sigs {
		result = append(result, signature.NewOCI11Signature(sig))
	}
	return result, nil
}
