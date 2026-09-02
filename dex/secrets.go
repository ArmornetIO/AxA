package dex

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ArmornetIO/identity"
)

// SecretResolver resolves a SecretRef to its plaintext value at write time.
type SecretResolver interface {
	Resolve(ctx context.Context, ref identity.SecretRef) (string, error)
}

// newSecretResolver reads env vars; embedded Dex resolves no Kubernetes Secrets.
func newSecretResolver() SecretResolver {
	return &envSecretResolver{}
}

// envSecretResolver reads uppercase(Name_Key), hyphens as underscores:
// {Name:"auth0", Key:"clientSecret"} is AUTH0_CLIENTSECRET.
type envSecretResolver struct{}

func (r *envSecretResolver) Resolve(_ context.Context, ref identity.SecretRef) (string, error) {
	key := strings.ToUpper(strings.ReplaceAll(ref.Name+"_"+ref.Key, "-", "_"))
	val := os.Getenv(key)
	if val == "" {
		return "", fmt.Errorf("env secret resolver: %s is not set (SecretRef{Name:%q, Key:%q})", key, ref.Name, ref.Key)
	}
	return val, nil
}

var _ SecretResolver = (*envSecretResolver)(nil)
