package envsecret_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gavincabbage/envsecret"
)

func TestPrivateKey_Decode(t *testing.T) {

	var (
		encodedTestPublicKey = map[string]interface{}{
			"public_key": testPrivateKey,
		}
		encodedJunk = map[string]interface{}{
			"public_key": "c29tZWp1bmsK",
		}
		incorrectlyEncodedJunk = map[string]interface{}{
			"public_key": "c29tZWp1bms!!K",
		}
	)

	subject := &envsecret.PrivateKey{}

	assert.NoError(t, subject.Decode(encodedTestPublicKey))
	assert.Error(t, subject.Decode(encodedJunk))
	assert.Error(t, subject.Decode(incorrectlyEncodedJunk))
}

func TestPublicKey_Decode(t *testing.T) {

	var (
		encodedTestPublicKey = map[string]interface{}{
			"public_key": testPublicKey,
		}
		encodedJunk = map[string]interface{}{
			"public_key": "c29tZWp1bmsK",
		}
		incorrectlyEncodedJunk = map[string]interface{}{
			"public_key": "c29tZWp1bms!!K",
		}
	)

	subject := &envsecret.PublicKey{}

	assert.NoError(t, subject.Decode(encodedTestPublicKey))
	assert.Error(t, subject.Decode(encodedJunk))
	assert.Error(t, subject.Decode(incorrectlyEncodedJunk))
}
