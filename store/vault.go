package vault

import (
	"errors"

	"github.com/hashicorp/vault/api"
)

// SecretsManager provides access to AWS Secrets Manager.
type Vault struct {
	client *api.Client
}

// NewSecretsManager returns a SecretsManager instance configured to use the given AWS Secrets Manager client.
func New(client *api.Client) *Vault {
	return &Vault{
		client: client,
	}
}

// Get retrieves the secret from AWS Secrets Manager for the given identifier, either an ARN or the
// configured name of the desired secret.
func (v *Vault) Get(id string) (map[string]interface{}, error) {
	s, err := v.client.Logical().Read(id)
	if err != nil {
		return nil, err
	} else if s == nil {
		return nil, errors.New("missing secret")
	}

	return s.Data, nil
}
