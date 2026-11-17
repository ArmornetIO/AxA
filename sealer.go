package axa

// ConfigSealer encrypts state that must be recoverable at rest (connector
// credentials replayed on every login, decisions, device codes). The host
// supplies the cipher so this module holds no key; nil means cleartext.
type ConfigSealer interface {
	// Seal's output carries whatever nonce and version framing Open needs.
	Seal(plaintext []byte) ([]byte, error)
	// Open passes through rows written before sealing was on, until re-sealed.
	Open(sealed []byte) ([]byte, error)
}
