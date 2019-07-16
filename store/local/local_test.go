package local_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	secretstore "github.com/gavincabbage/envsecret/store/local"
)

func TestLocal_Get(t *testing.T) {
	cases := []struct {
		name     string
		val      string
		expected map[string]interface{}
	}{
		{
			name: "happy path map",
			val:  "{\"key\":\"value\"}",
			expected: map[string]interface{}{
				"key": "value",
			},
		},
		{
			name: "happy path string",
			val:  "value",
			expected: map[string]interface{}{
				"*": "value",
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			subject := secretstore.LocalStore{}

			actual, err := subject.Get(test.val)

			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
