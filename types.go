package envsecret

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// Secret is the interface considered by Process. Custom secret types
// can implement this interface to be populated by Process.
type Secret interface {
	// Decode should populate the secret based on the values in the string map returned by
	// the secrets provider. For example, PublicKey constructs an *rsa.PublicKey
	// from the raw base64 encoded string it looks for in the map.
	Decode(map[string]interface{}) error
	// ID should return the identifier of the secret to be retrieved.
	ID() string
}

// Base type for all Secret implementations exposed by this package.
type Base struct {
	id string
}

// NewBase returns a new Base secret with the given identifier.
func NewBase(id string) Base {
	return Base{id}
}

// Decode implements envconfig.Decoder and populates id.
func (s *Base) Decode(value string) error { s.id = value; return nil }

// ID returns the secret's identifier in the secret store being used,
// e.g. an ARN if using AWS Secrets Manager or a Vault secret path.
func (s *Base) ID() string { return s.id }

// String is a general purpose secret and holds a single string value.
type String struct {
	Base
	Value string
}

// NewString builds a new String type secret with the given id.
func NewString(id string) String {
	return String{Base: Base{id: id}}
}

// Decode implements Secret and populates Key with the secret string.
func (s *String) Decode(secrets map[string]interface{}) error {
	fmt.Println("decode", secrets)
	if s.Value = find(secrets, "value"); s.Value == "" {
		fmt.Println(s.Value)
		fmt.Println("ERROR")
		return errors.New("finding secret in map")
	}
	fmt.Println(s.Value)
	return nil
}

// Map contains a map of secret strings, possibly filtered by an allowList.
type Map struct {
	Base
	Values map[string]interface{}
}

// NewMap builds a new Map type secret with the given id.
func NewMap(id string) Map {
	return Map{Base: Base{id: id}}
}

// Decode implements Secret and populates Values with the secret map.
func (m *Map) Decode(secrets map[string]interface{}) error {
	m.Values = secrets
	return nil
}

// Login contains a username and password.
type Login struct {
	Base
	Username string
	Password string
}

// NewLogin builds a new DatabaseLogin type secret with the given id.
func NewLogin(id string) Login {
	return Login{Base: Base{id: id}}
}

// Decode implements Secret and populates the database credentials and host information.
func (l *Login) Decode(secrets map[string]interface{}) error {
	var (
		username, foundUsername = secrets["username"]
		password, foundPassword = secrets["password"]
	)
	if !foundUsername || !foundPassword {
		return errors.New("finding username or password in map")
	}

	l.Username, l.Password = str(username), str(password)

	return nil
}

// PublicKey contains an RSA public key.
type PublicKey struct {
	Base
	Key *rsa.PublicKey
}

// NewPublicKey builds a new PublicKey type secret with the given id.
func NewPublicKey(id string) PublicKey {
	return PublicKey{Base: Base{id: id}}
}

// Decode implements Secret and populates Key with the constructed public key.
func (k *PublicKey) Decode(secrets map[string]interface{}) error {
	value := find(secrets, "public_key")
	if value == "" {
		return errors.New("finding secret in map")
	}

	bytes, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return err
	}

	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return errors.New("decoding pem")
	}

	var (
		parsed interface{}
		ok     bool
	)
	if parsed, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return err
	} else if k.Key, ok = parsed.(*rsa.PublicKey); !ok {
		return errors.New("parsing public key")
	}

	return nil
}

// PrivateKey contains a secret RSA private key.
type PrivateKey struct {
	Base
	Key *rsa.PrivateKey
}

// NewPrivateKey builds a new PrivateKey type secret with the given id.
func NewPrivateKey(id string) PrivateKey {
	return PrivateKey{Base: Base{id: id}}
}

// Decode implements Secret and populates Key with the constructed private key.
func (k *PrivateKey) Decode(secrets map[string]interface{}) error {
	value := find(secrets, "private_key")
	if value == "" {
		return errors.New("finding secret in map")
	}

	bytes, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return err
	}

	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return errors.New("decoding pem")
	}

	var parsed interface{}
	if parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return err
		}
	}

	var ok bool
	if k.Key, ok = parsed.(*rsa.PrivateKey); !ok {
		return errors.New("parsing private key")
	}

	return nil
}

// find a secret value in a map - if there is only one option, return it, else return
// the value of the given key (which may be an empty string if no corresponding value exists)
func find(secrets map[string]interface{}, key string) string {
	if len(secrets) == 1 {
		for _, v := range secrets {
			return str(v)
		}
	} else if v, found := secrets[key]; found {
		return str(v)
	}

	return ""
}

func str(x interface{}) string {
	return fmt.Sprintf("%v", x)
}
