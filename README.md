# pkg `envsecret`

**tl;dr** Exposes `envsecret.Process`, designed to follow `envconfig.Process` and retrieve 
secrets from cloud providers such as Vault and AWS Secrets Manager.

# Summary

Package `secret` wraps interaction with AWS Secrets Manager and is designed to complement `envconfig`, 
though it can work independently.

Define a configuration specification suitable for `envconfig`, but using an 
implementation of this package's `Secret` interface in place of any remotely stored secrets. 
The package provides a few of these for common use cases (`String`, `PublicKey`, etc.) but custom types
are also possible.

Instead of configuring the secret *value* in the environment variable, configure it's secret *identifier*:
either the ARN or the configured name of the secret in AWS Secrets Manager. 
Processing by envconfig should populate each `Secret`'s identifier by by implementing `envconfig.Decoder`.

Finally, calling `envsecret.Process` will retrieve each requested secret and populate it 
according to it's `Decode` method.

By default, all secrets are **NOT** required. This means an error will only be returned if a secret is marked as `required:"true"` in the configuration struct tags.

# Example

Given the following environment configuration and secrets configured in AWS Secrets Manager:

```bash
APP_DEBUG=true
AWS_REGION=us-west-2
APP_SOME_SECRET=somesecret-name-in-aws
APP_REQUIRED_SECRET=requiredsecret-name-in-aws
APP_ANOTHER_SECRET=somesecret-name-in-aws
APP_PUBLIC_KEY=mykeypair
APP_CREDENTIALS=database-credentials-123
```

The code below will populate the configuration struct with the requested secret values:

```go
// Configure a specification struct for envconfig.
type Config struct {

	// Non-secret types can be mixed freely with secret types.
	Debug  bool
	Region string `envconfig:"AWS_REGION" default:"us-east-1"`

	// SomeSecret will default to the "value" key found in the secret named "somesecret-name-in-aws"
	SomeSecret envsecret.String `split_words:"true"`

	// RequiredSecret will cause an error if its key "requiredsecret-name-in-aws" is not present in the config.
	RequiredSecret envsecret.String `split_words:"true" required:"true"`

	// AnotherSecret will also use the secret found at "somesecret-name-in-aws" but with a different
	// key than the default, "some_other_key"
	AnotherSecret envsecret.String `split_words:"true" secret_keys:"some_other_key"`

	// The PublicKey type expects a base64 encoded key and will construct an *rsa.PublicKey from it.
	PublicKey envsecret.PublicKey `split_words:"true"`

	// Login provides a username and password pair.
	Credentials envsecret.Login
}

func main() {

	// Process as normal with envconfig. This will populate the identifiers necessary for secret retrieval.
	var config Config
	envconfig.MustProcess("app", &config)

	// Set up a secret Store, in this case AWS Secrets Manager.
	awsSession, _ := session.NewSession(aws.NewConfig().WithRegion(config.Region))
	sm := secretsmanager.New(awsSession)
	secretStore := envsecret.NewSecretsManager(sm)

	// Retrieve the secrets from the Store and populate the config with their secret values.
	envsecret.MustProcess(&config, secretStore)

	// Types implementing Secret determine how to populate themselves via their implementation of Decode.
	// For example, the envsecret.String type populates a Value field with the secret string value,
	// and envsecret.PublicKey populates a Key field with a constructed rsa.PublicKey.
	fmt.Println(config.SomeSecret.Value)
	fmt.Println(config.PublicKey.Key)
}
```






