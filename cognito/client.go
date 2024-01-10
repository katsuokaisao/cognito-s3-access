package cognito

import (
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/katsuokaisao/cognito-s3-access-study/domain"
	"github.com/katsuokaisao/cognito-s3-access-study/repository"
)

type cognitoClient struct {
	provider *cognitoidentityprovider.CognitoIdentityProvider
	identity *cognitoidentity.CognitoIdentity

	accountID    string
	region       string
	poolID       string
	clientID     string
	clientSecret string

	mu            sync.RWMutex
	userTokenMap  map[string]*domain.UserToken
	credentialMap map[string]*domain.Credential
}

func NewCognitoClient(region, accountID, poolID, clientID, client_secret string) repository.CognitoClient {
	provider := cognitoidentityprovider.New(
		session.Must(
			session.NewSession(
				&aws.Config{
					Region: aws.String(region),
				},
			),
		),
	)

	identity := cognitoidentity.New(
		session.Must(
			session.NewSession(
				&aws.Config{
					Region: aws.String(region),
				},
			),
		),
	)

	return &cognitoClient{
		provider:      provider,
		identity:      identity,
		accountID:     accountID,
		region:        region,
		poolID:        poolID,
		clientID:      clientID,
		clientSecret:  client_secret,
		userTokenMap:  make(map[string]*domain.UserToken),
		credentialMap: make(map[string]*domain.Credential),
	}
}

func (c *cognitoClient) getUserTokenFromMap(username string) (*domain.UserToken, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	userToken, ok := c.userTokenMap[username]
	return userToken, ok
}

func (c *cognitoClient) setUserToken(username string, userToken *domain.UserToken) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.userTokenMap[username] = userToken
}

func (c *cognitoClient) deleteUserToken(username string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.userTokenMap, username)
}

func (c *cognitoClient) getCredentialFromMap(idToken string) (*domain.Credential, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	credential, ok := c.credentialMap[idToken]
	return credential, ok
}

func (c *cognitoClient) setCredential(idToken string, credential *domain.Credential) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.credentialMap[idToken] = credential
}

func (c *cognitoClient) deleteCredential(idToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.credentialMap, idToken)
}
