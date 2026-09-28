package fga

import _ "embed"

//go:embed schema.sql
var schemaSQL string

// Schema is reference DDL the host runs (see pgstore.Schema). Idempotent, but it
// never upgrades a table that exists in an older shape.
func Schema() string { return schemaSQL }
