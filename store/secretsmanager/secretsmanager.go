package secretsmanager

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// SecretsManager provides access to AWS Secrets Manager.
type SecretsManager struct {
	client awsSecretsManager
}

// NewSecretsManager returns a SecretsManager instance configured to use the given AWS Secrets Manager client.
func New(sm awsSecretsManager) *SecretsManager {
	return &SecretsManager{
		client: sm,
	}
}

// Get retrieves the secret from AWS Secrets Manager for the given identifier, either an ARN or the
// configured name of the desired secret.
func (s *SecretsManager) Get(id string) (map[string]interface{}, error) {
	out, err := s.client.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(id),
	})
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(*out.SecretString), &m); err != nil {
		return nil, err
	}

	return m, nil
}

type awsSecretsManager interface {
	GetSecretValue(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)
}
