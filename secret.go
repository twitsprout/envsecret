package envsecret

import (
	"errors"
	"reflect"
	"strings"
)

const tag = "secret_keys"

var (
	ErrMissingID         = errors.New("requires a non-empty retrieval identifier")
	ErrRequiresStructPtr = errors.New("requires a pointer to a config specification struct")
	ErrMaxOneKey         = errors.New("secret type requires at most one override key")
	ErrNoOverride        = errors.New("secret type does not allow key overrides")
)

type cacheMap map[string]map[string]interface{}

// Store of secrets.
type Store interface {
	// Get should return the map of secret values for the given identifier.
	Get(string) (map[string]interface{}, error)
}

// MustProcess calls Process and panics on any error.
func MustProcess(spec interface{}, store Store) {
	if err := Process(spec, store); err != nil {
		panic(err)
	}
}

// Process takes a pointer to a configuration specification and populates Secrets in the underlying struct.
func Process(spec interface{}, store Store) error {
	ptr := reflect.ValueOf(spec)
	if ptr.Kind() != reflect.Ptr {
		return ErrRequiresStructPtr
	}

	V := ptr.Elem()
	if V.Kind() != reflect.Struct {
		return ErrRequiresStructPtr
	}

	cache := make(cacheMap)

	for i := 0; i < V.NumField(); i++ {
		field := V.Type().Field(i)
		if field.Tag.Get("ignored") == "true" {
			continue
		}

		required := (field.Tag.Get("required") == "true")

		if secret := secretFrom(V.Field(i)); secret != nil {
			if secret.ID() == "" {
				if !required {
					continue
				}

				return ErrMissingID
			}

			allowList := parseAllowList(field)
			switch secret.(type) {
			case *String, *PublicKey, *PrivateKey:
				if len(allowList) > 1 {
					return ErrMaxOneKey
				}
			case *Login:
				if len(allowList) > 0 {
					return ErrNoOverride
				}
			}

			val, err := get(secret, store, allowList, cache)
			if err != nil {
				return err
			}

			if err := secret.Decode(val); err != nil {
				return err
			}
		}
		// TODO Process recursively to support nested structs.
	}

	return nil
}

// get the requested secret from the store and filters the results.
func get(s Secret, store Store, allowList []string, cache cacheMap) (v map[string]interface{}, e error) {
	v, cached := cache[s.ID()]
	if !cached {
		v, e = store.Get(s.ID())
		if e != nil {
			return
		}
		cache[s.ID()] = v
	}

	return filter(v, allowList), nil
}

// filter the map according to the allowList, if provided.
func filter(m map[string]interface{}, allowList []string) (filtered map[string]interface{}) {
	if allowList != nil {
		filtered = make(map[string]interface{})
		for _, key := range allowList {
			v, found := m[key]
			if found {
				filtered[key] = v
			}
		}
	} else {
		filtered = m
	}

	return
}

// secretFrom returns the field value cast to a Secret, or nil if impossible
func secretFrom(field reflect.Value) (s Secret) {
	if field.CanAddr() && field.Addr().CanInterface() {
		s, _ := field.Addr().Interface().(Secret)
		return s
	}
	return nil
}

// parseAllowList returns a slice of strings from the comma separated tag string, or nil if the tag is empty
func parseAllowList(field reflect.StructField) []string {
	if t := field.Tag.Get(tag); t != "" {
		return strings.Split(string(t), ",")
	}
	return nil
}
