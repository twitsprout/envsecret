package envsecret_test

import (
	"fmt"
	"os"

	"github.com/kelseyhightower/envconfig"

	"github.com/gavincabbage/envsecret"
	secretstore "github.com/gavincabbage/envsecret/store/local"
)

func init() {
	_ = os.Setenv("APP_DEBUG", "true")
	_ = os.Setenv("AWS_REGION", "us-west-2")
	_ = os.Setenv("APP_SOME_SECRET", "somesecret-name-in-aws")
	_ = os.Setenv("APP_REQUIRED_SECRET", "requiredsecret-name-in-aws")
	_ = os.Setenv("APP_ANOTHER_SECRET", "somesecret-name-in-aws")
	_ = os.Setenv("APP_PUBLIC_KEY", "mykeypair")
	_ = os.Setenv("APP_CREDENTIALS", "database-credentials-123")
}

// config is a specification struct for environment secrets.
type config struct {
	// Non-secret types can be mixed freely with secret types.
	Debug  bool
	Region string `envconfig:"AWS_REGION" default:"us-east-1"`

	// SomeSecret will default to the "value" key found in the secret named "somesecret-name-in-aws"
	SomeSecret envsecret.String `split_words:"true"`

	// RequiredSecret will cause an error if its key "requiredsecret-name-in-aws" is not present in the config.
	RequiredSecret envsecret.String `split_words:"true" required:"true"`

	// AnotherSecret will also use the secret found at "somesecret-name-in-aws" but with a different
	// key than the default, "value"
	AnotherSecret envsecret.String `split_words:"true" secret_keys:"some_other_key"`

	// The PublicKey type expects a base64 encoded key and will construct an *rsa.PublicKey from it.
	PublicKey envsecret.PublicKey `split_words:"true"`

	// Login provides a username and password pair.
	Credentials envsecret.Login
}

func Example() {

	// Process as normal with envconfig. This will populate the identifiers necessary for secret retrieval.
	var c config
	envconfig.MustProcess("app", &c)

	// TODO this example isn't particularly meaningful if we use a local store, but a real store also isn't practical so...? maybe mock one to illustrate?
	// Set up a secret Store, in this case a dummy local store.
	secretStore := secretstore.New()

	// Retrieve the secrets from the Store and populate the config with their secret values.
	envsecret.MustProcess(&c, secretStore)

	// Types implementing Secret determine how to populate themselves via their implementation of Decode.
	// For example, the envsecret.String type populates a Value field with the secret string value,
	// and envsecret.PublicKey populates a Key field with a constructed rsa.PublicKey.
	fmt.Println(c.SomeSecret.Value)
	fmt.Println(c.PublicKey.Key)
}
