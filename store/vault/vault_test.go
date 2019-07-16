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
			id:   "secret/data/hello",
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
				t.Fatal(err)
			}

			client.SetToken(os.Getenv("VAULT_DEV_ROOT_TOKEN_ID"))

			wrapped := map[string]interface{}{
				"data": test.expected,
			}
			if _, err := client.Logical().Write(test.id, wrapped); err != nil {
				t.Fatal(err)
			}

			subject := secretstore.New(client)

			response, err := subject.Get(test.id)
			assert.NoError(t, err)

			actual, present := response["data"]
			if !present {
				t.Fatal("missing secret data")
			}
			assert.Equal(t, test.expected, actual)
		})
	}
}
