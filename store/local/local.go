package local

import "encoding/json"

// LocalStore is a fake implementation of Store for local development.
type LocalStore struct{}

// New returns a new LocalStore
func New() *LocalStore {
	return &LocalStore{}
}

// Get unmarshals the identifier and returns it directly as the secret map.
func (*LocalStore) Get(value string) (map[string]interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(value), &m); err != nil {
		return map[string]interface{}{
			"*": value,
		}, nil
	}

	return m, nil
}
