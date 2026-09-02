package fga

import _ "embed"

//go:embed model.default.fga
var defaultModel []byte

// DefaultModel is a minimal user / organization / platform baseline, used when
// Config.ModelData is empty.
func DefaultModel() []byte { return defaultModel }
