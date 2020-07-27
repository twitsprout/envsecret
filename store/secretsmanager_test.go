package secretsmanager_test

import (
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	secretstore "github.com/gavincabbage/envsecret/store/secretsmanager"
)

const (
	region   = "us-east-1"
	endpoint = "http://secretsmanager:4584"
)

func TestSecretsManager_Get(t *testing.T) {
	_ = os.Setenv("AWS_ACCESS_KEY_ID", "bogus")
	_ = os.Setenv("AWS_SECRET_ACCESS_KEY", "bogus")

	var (
		awsConfig = aws.NewConfig().
				WithRegion(region).
				WithDisableSSL(true).
				WithCredentials(credentials.NewEnvCredentials())
		awsSession, _ = session.NewSession(awsConfig)
		client        = secretsmanager.New(awsSession)
	)
	client.Endpoint = endpoint

	out, err := client.CreateSecret(&secretsmanager.CreateSecretInput{
		Name:         aws.String("identifier"),
		SecretString: aws.String("{\"key\":\"value\"}"),
	})
	if err != nil {
		t.Error("putting test secrets")
	}
	t.Log(out)

	cases := []struct {
		name     string
		id       string
		expected map[string]interface{}
	}{
		{
			name: "happy path",
			id:   "identifier",
			expected: map[string]interface{}{
				"key": "value",
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			subject := secretstore.New(client)

			actual, err := subject.Get(test.id)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}

}
