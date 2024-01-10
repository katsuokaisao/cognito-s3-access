package cognito

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/katsuokaisao/cognito-s3-access-study/domain"
)

func (c *cognitoClient) GetCredentials(idToken string) (*domain.Credential, error) {
	credential, ok := c.getCredentialFromMap(idToken)
	if ok {
		if credential.Expiration.After(time.Now()) {
			return credential, nil
		} else {
			c.deleteCredential(idToken)
		}
	}

	identityID, err := c.getID(idToken)
	if err != nil {
		return nil, err
	}

	getCredentialsForIdentityOutput, err := c.getCredentialsForIdentity(identityID, idToken)
	if err != nil {
		return nil, err
	}

	credential = &domain.Credential{
		AccessKeyID:  *getCredentialsForIdentityOutput.Credentials.AccessKeyId,
		SecretKey:    *getCredentialsForIdentityOutput.Credentials.SecretKey,
		SessionToken: *getCredentialsForIdentityOutput.Credentials.SessionToken,
		Expiration:   *getCredentialsForIdentityOutput.Credentials.Expiration,
	}

	c.setCredential(identityID, credential)

	return credential, nil
}

func (c *cognitoClient) getID(idToken string) (string, error) {
	input := &cognitoidentity.GetIdInput{}
	input.SetAccountId(c.accountID)
	input.SetIdentityPoolId(c.poolID)
	input.SetLogins(map[string]*string{
		fmt.Sprintf("cognito-idp.%s.amazonaws.com/%s", c.region, c.poolID): aws.String(idToken),
	})

	getIDOutput, err := c.identity.GetId(input)
	if err != nil {
		return "", fmt.Errorf("get id error: %v", err)
	}
	if getIDOutput.IdentityId == nil {
		return "", fmt.Errorf("identity id is nil")
	}

	return *getIDOutput.IdentityId, nil
}

func (c *cognitoClient) getCredentialsForIdentity(identityID, idToken string) (*cognitoidentity.GetCredentialsForIdentityOutput, error) {
	input := &cognitoidentity.GetCredentialsForIdentityInput{}
	input.SetIdentityId(identityID)
	input.SetLogins(map[string]*string{
		fmt.Sprintf("cognito-idp.%s.amazonaws.com/%s", c.region, c.poolID): aws.String(idToken),
	})

	getCredentialsForIdentityOutput, err := c.identity.GetCredentialsForIdentity(input)
	if err != nil {
		return nil, fmt.Errorf("get credentials for identity error: %v", err)
	}

	return getCredentialsForIdentityOutput, nil
}
