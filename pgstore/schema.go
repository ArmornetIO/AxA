package pgstore

import _ "embed"

//go:embed schema.sql
var schemaSQL string

// Schema is a contract the host applies its own way (armornet: dbmgr). Idempotent,
// but it never upgrades a table that exists in an older shape.
func Schema() string { return schemaSQL }
