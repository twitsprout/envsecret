package vault_test

import (
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"

	secretstore "github.com/gavincabbage/envsecret/store/vault"
)

const endpoint = "http://vault:8200"

func TestVault_Get(t *testing.T) {
	cases := []struct {
		name     string
		id       string
		expected map[string]interface{}
	}{
		{
			name: "happy path",
			id:   "/secret/data/identifier",
			expected: map[string]interface{}{
				"key": "value",
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client, err := api.NewClient(&api.Config{
				Address: endpoint,
			})
			if err != nil {
				t.Error(err)
				t.FailNow()
			}

			client.SetToken(os.Getenv("VAULT_DEV_ROOT_TOKEN_ID"))

			if _, err := client.Logical().Write(test.id, test.expected); err != nil {
				t.Error(err)
				t.FailNow()
			}

			subject := secretstore.New(client)

			actual, err := subject.Get(test.id)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
