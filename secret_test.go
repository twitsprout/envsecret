package envsecret_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gavincabbage/envsecret"
)

func TestMustProcess(t *testing.T) {
	assert.Panics(t, func() {
		envsecret.MustProcess(nil, nil)
	})
}

func TestProcess_Errors(t *testing.T) {

	type testSpec struct {
		DefaultString    envsecret.String
		OverriddenString envsecret.String `secret_keys:"otherkey"`
		RequiredString   envsecret.String `required:"true"`
	}

	tests := []struct {
		name  string
		store *spySecretStore
		spec  testSpec
	}{
		{
			name: "store error",
			store: &spySecretStore{
				Out: map[string]map[string]interface{}{
					"secret-id": {
						"value":    "default secret value",
						"otherkey": "other value",
					},
				},
				Err: errors.New("retrieval error"),
			},
			spec: testSpec{
				DefaultString:    envsecret.NewString("bad-id"),
				OverriddenString: envsecret.NewString("bad-id"),
				RequiredString:   envsecret.NewString("bad-id"),
			},
		},
		{
			name: "missing specified override key",
			store: &spySecretStore{
				Out: map[string]map[string]interface{}{
					"secret-id": {
						"value": "default secret value",
					},
				},
			},
			spec: testSpec{
				DefaultString:    envsecret.NewString("secret-id"),
				OverriddenString: envsecret.NewString("secret-id"),
				RequiredString:   envsecret.NewString("secret-id"),
			},
		},
		{
			name: "missing required key",
			store: &spySecretStore{
				Out: map[string]map[string]interface{}{
					"secret-id": {
						"value":    "default secret value",
						"otherkey": "other value",
					},
				},
			},
			spec: testSpec{
				DefaultString:    envsecret.NewString("secret-id"),
				OverriddenString: envsecret.NewString("secret-id"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := envsecret.Process(&test.spec, test.store)
			assert.Error(t, err)
		})
	}
}

func TestProcess(t *testing.T) {

	store := &spySecretStore{
		Out: map[string]map[string]interface{}{
			"default-string-id": {
				"value": "default secret value",
			},
			"override-string-id": {
				"overridden": "overridden secret value",
				"value":      "default secret value",
			},
			"public-key-id": {
				"value": testPublicKey,
			},
			"private-key-id": {
				"value": testPrivateKey,
			},
			"login-id": {
				"username": "testUser",
				"password": "testPassword",
			},
			"default-map-id": {
				"key1": "val1",
				"key2": "val2",
				"key3": "val3",
			},
			"filtered-map-id": {
				"key1": "val1",
				"key2": "val2",
				"key3": "val3",
			},
			"rds-login-id": {
				"engine":   "postgres",
				"username": "testUser",
				"password": "testPassword",
				"host":     "testHost",
				"port":     "testPort",
				"dbname":   "testDb",
			},
		},
	}

	testSpec := struct {
		NotSecret        string
		AnotherNotSecret int
		ThirdNotSecret   struct{ string }

		DefaultString               envsecret.String
		DummyDefaultString          envsecret.String
		OverrideString              envsecret.String    `secret_keys:"overridden"`
		PublicKey                   envsecret.PublicKey `required:"true"`
		PrivateKey                  envsecret.PrivateKey
		Login                       envsecret.Login
		DefaultMap                  envsecret.Map
		FilteredMap                 envsecret.Map    `secret_keys:"key1,key3"`
		IgnoredSecret               envsecret.String `ignored:"true"`
		ExplicitlyNotRequiredSecret envsecret.String `required:"false"`
	}{
		NotSecret:        "some string",
		AnotherNotSecret: 42,
		ThirdNotSecret:   struct{ string }{"string inside"},

		DefaultString:      envsecret.NewString("default-string-id"),
		DummyDefaultString: envsecret.NewString("default-string-id"),
		OverrideString:     envsecret.NewString("override-string-id"),
		PublicKey:          envsecret.NewPublicKey("public-key-id"),
		PrivateKey:         envsecret.NewPrivateKey("private-key-id"),
		Login:              envsecret.NewLogin("login-id"),
		DefaultMap:         envsecret.NewMap("default-map-id"),
		FilteredMap:        envsecret.NewMap("filtered-map-id"),
	}

	err := envsecret.Process(&testSpec, store)
	assert.NoError(t, err)
	assert.Equal(t, 7, store.GetCount) // duplicate secret id retrievals should be cached

	// Didn't affect non-secrets
	assert.Equal(t, "some string", testSpec.NotSecret)
	assert.Equal(t, 42, testSpec.AnotherNotSecret)
	assert.Equal(t, "string inside", testSpec.ThirdNotSecret.string)

	// String
	assert.Equal(t, "default secret value", testSpec.DefaultString.Value)
	assert.Equal(t, "overridden secret value", testSpec.OverrideString.Value)

	// PublicKey
	assert.NotNil(t, testSpec.PublicKey.Key)

	// PrivateKey
	assert.NotNil(t, testSpec.PrivateKey.Key)

	// Login
	assert.Equal(t, "testUser", testSpec.Login.Username)
	assert.Equal(t, "testPassword", testSpec.Login.Password)

	// Map
	assert.Equal(t, 3, len(testSpec.DefaultMap.Values))
	assert.Equal(t, 2, len(testSpec.FilteredMap.Values))
}

func (spy *spySecretStore) Get(id string) (map[string]interface{}, error) {
	spy.GetCount++
	if spy.Err != nil {
		return nil, spy.Err
	}
	return spy.Out[id], nil
}

type spySecretStore struct {
	Out      map[string]map[string]interface{}
	Err      error
	GetCount int
}

const (
	testPublicKey  = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF5ZkpSMTAwZWFldFJmWHl2blZzRgpPaWZrVkdBeUFiNTk0RGRDMHdKSDNWdVFDRys4Y1RGUUY0aXd5MmRpNGJKbktsVHNhUlp4dERnaWJKTFRCeEw4CnlHRy9wT1dSVHdkRDErS2xKdmt4Vmp2N05uUmhFM1VTeG1zdllYN2FURWNKSWFVdUVJUmFJQlZxMW1rUFptUTMKRHJOM2dPNlZEK0hHYjkrTytRTHMwbEtuSWlJc3JmK3Q0SGdINnNIUVpWdVdIWlVIcVZ4QTVjNTRFWUJoUDVtdQptYlJ4QUVCbmEyVm02MkxaSXdiVGs5SHVuL1JxVmZsYkZCdkdaaitVSDN6U0VGemtjQThUekg3RjJBcGpkc2NiCnowT0NkZ0FBR1EzZndMWFZFaCtDQmpxa21QeVQyWlBqWDg4YUlLQVJEemxPbHMwZXI3aTNwanJlczBCblRVUnIKQVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
	testPrivateKey = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBeWZKUjEwMGVhZXRSZlh5dm5Wc0ZPaWZrVkdBeUFiNTk0RGRDMHdKSDNWdVFDRys4CmNURlFGNGl3eTJkaTRiSm5LbFRzYVJaeHREZ2liSkxUQnhMOHlHRy9wT1dSVHdkRDErS2xKdmt4Vmp2N05uUmgKRTNVU3htc3ZZWDdhVEVjSklhVXVFSVJhSUJWcTFta1BabVEzRHJOM2dPNlZEK0hHYjkrTytRTHMwbEtuSWlJcwpyZit0NEhnSDZzSFFaVnVXSFpVSHFWeEE1YzU0RVlCaFA1bXVtYlJ4QUVCbmEyVm02MkxaSXdiVGs5SHVuL1JxClZmbGJGQnZHWmorVUgzelNFRnprY0E4VHpIN0YyQXBqZHNjYnowT0NkZ0FBR1EzZndMWFZFaCtDQmpxa21QeVQKMlpQalg4OGFJS0FSRHpsT2xzMGVyN2kzcGpyZXMwQm5UVVJyQVFJREFRQUJBb0lCQURGdEJXclVqU1VQV3hxRApjZGZwZHhZTXZXMkpQYlAvazM5VkJ4M3Q2UGpjZUJ3WWZONlhXeXJuWVozbTUrU2xiV3FHN25XcDhKcFRRdG1mCjlkWTlaM0VEdTR2NFErQTd2dmNQbWF3NFFVTUIyekl3dWJHeGJhN3lmTjQzMWVYbFhPN0hKc2NVSFpyTW95Rm4KQlVYaU1UZC81VGZCTE9wK0w3c2gxRFJONnZodW91cUR6K1JhWG90SU9Cc3lTVTh6R1l6aElFaVdMdEpnYTFaRApnL0VZRXRKTDlkR2dqaFQ5Y3d1VTNTTm83Q1hjdHRlTElOSUFRYm5DM3RuTnpzZkZyN2lXbUc4S1JxWUZNSXAvCjZncFZGTE1RR0EyQVVYVWxWampITzFFbGNUMEE4NkQ4Vnp5a0QrNmxLaGpkaWFFWENoQ0hnZlRnU0UrZjN3USsKdUN2L0ZLRUNnWUVBNjZNanJ5ZlROTG1HRjNiS2xkaWlTcDZNdGhKUXJidGI4cEVKcUJEVzAxYjdmemE5N2U0RwpxcldOWFRmS0gwcUF0eElBY20wZnBuZGtBckR4cXFJdkNUd2d3SzFDdENZdXEvT0FFWjZMMmdWdmEyclBJeVBLCkcvSzVZWXdjakdvWHNjOHV2Zlk1TTBSQU1LM1JSN21Jc21TeTg3TisvelU3SUd5dU9USjlzYWNDZ1lFQTIyWGMKZlNOd3ZIbzJjeVREOVBDZ28vcTJaSlpOdVJQODFoYmoydkhMRjk4Rjd5VDBmNGVuNVU2YS9xamZ3bnAxNmZ2NwpmdW43ZTBCVXpWWmMrQlZ0bGNqRlFLZVBINjFHS2oybmZIUkZmS1dlU1dOcGtld1hSemZmeVJCSEdsZksxcXJuCjRQc00yM25WUUk3blF1aWp5cTJzRVVCZkRGUkVsYnd6ZjRXSGd4Y0NnWUEzWW9VRXFtdXVQTjBUcnN3M0pGQWgKRWRzcEFHME9LTGVYOEJkQTlaUkk0RzBFbmExT3UxKzl5Q2FOL29yM2g5OXhLRDRLcHpPRlFSSzB2enBPVFFpWgpOeFRMdE8yMHdqUytIZUhBUW0vRXN2cFpXU1dPc043VWF0eS8zTnJvOWhiVHFFcm9RM04yWlZoaEdMblVEZnZmClVtUHRmQWNoblRWa2phYjFzclJ3aVFLQmdRQ2YrUlBlUXZzdTBzWGxDMGUrejcyeUUxcnUyUkZ2QS8zMWROZEwKaThhVWIwLzZZYTNOVjNLNnBxZ3BTNlZzUHJLL203WnpnZFNXdC8rZGdYMWtmdXRhcmZ2MStyZEhWNmF6b2lULwpnQ0F5bE9obmhvOHhrVDRmOWNPODdadUt2N3pzN2MwSnBNUnBPOXFjcWhaQ0dUTmswMkdGYXJSalh3WnJUOEVWCkdKNEluUUtCZ0J6OVlyRVZZOW9ubDhvSDZncm8rV2lrMlo5OGFrUm1GOVJ1bDEyVnFVVXE4RUM5VnQ1MlI0a3AKSG9SZE9YUzgrUzJWK0JrZ2VrMjNSRjhyclVPR2NvWGloU3oxMnI1c1NDeXRDNG9Dd2tjaFVpc0dsNlFTSGM3NAo2UTBpR1JxcFFNK2J4T3dKMElPdXcvVzFmb0toL0I0d2syeFEwY3JycEp4cEt0QmxsZS81Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="
)
