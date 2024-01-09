package cognito

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	cognitosrp "github.com/alexrudd/cognito-srp/v3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

func (c *cognitoClient) GetUserToken(username, password string) (*UserToken, error) {
	userToken, ok := c.getUserTokenFromMap(username)

	if ok {
		if userToken.Expiration.After(time.Now()) {
			return userToken, nil
		}

		// トークンが期限切れの場合は、リフレッシュトークンを使用して新しいトークンを取得する
		userToken, err := c.getRefreshTokenAuth(username, userToken.RefreshToken)
		if err != nil {
			// ログだけ出して getUserSRPAuth で新しいトークンを取得する
			fmt.Printf("refresh token error: %v\n", err)
			c.deleteCredential(username)
		} else {
			c.setUserToken(username, userToken)

			return userToken, nil
		}
	}

	userToken, err := c.getUserSRPAuth(username, password)
	if err != nil {
		return nil, err
	}
	if userToken == nil {
		return nil, fmt.Errorf("cat not fetch token")
	}

	c.setUserToken(username, userToken)

	return userToken, nil
}

func (c *cognitoClient) getUserSRPAuth(username, password string) (*UserToken, error) {
	authOutput, err := c.userSRPAuth(username, password)
	if err != nil {
		return nil, err
	}

	if authOutput.ChallengeName != nil {
		return nil, fmt.Errorf("challenge name is not nil: %v", *authOutput.ChallengeName)
	}

	if authOutput.AuthenticationResult == nil ||
		*authOutput.AuthenticationResult.IdToken == "" ||
		*authOutput.AuthenticationResult.AccessToken == "" ||
		*authOutput.AuthenticationResult.RefreshToken == "" ||
		*authOutput.AuthenticationResult.ExpiresIn == 0 {
		return nil, fmt.Errorf("token is nil")
	}

	return &UserToken{
		AccessToken:  *authOutput.AuthenticationResult.AccessToken,
		IDToken:      *authOutput.AuthenticationResult.IdToken,
		RefreshToken: *authOutput.AuthenticationResult.RefreshToken,
		Expiration:   time.Now().Add(time.Duration(*authOutput.AuthenticationResult.ExpiresIn) * time.Second),
	}, nil
}

func (c *cognitoClient) userSRPAuth(username, password string) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	authFlow := "USER_SRP_AUTH"

	csrp, err := cognitosrp.NewCognitoSRP(username, password, c.poolID, c.clientID, &c.clientSecret)
	if err != nil {
		return nil, fmt.Errorf("cognito srp error: %v", err)
	}

	// https://github.com/alexrudd/cognito-srp
	authInputParams := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       aws.String(authFlow),
		AuthParameters: csrp.GetAuthParams(),
		ClientId:       aws.String(c.clientID),
	}
	authOutput, err := c.provider.InitiateAuth(authInputParams)
	if err != nil {
		return nil, fmt.Errorf("admin initiate auth error: %v", err)
	}

	return authOutput, nil
}

func (c *cognitoClient) getRefreshTokenAuth(username, refreshToken string) (*UserToken, error) {
	authOutput, err := c.refreshTokenAuth(username, refreshToken)
	if err != nil {
		return nil, err
	}

	if authOutput.ChallengeName != nil {
		return nil, fmt.Errorf("challenge name is not nil: %v", *authOutput.ChallengeName)
	}

	if authOutput.AuthenticationResult == nil ||
		*authOutput.AuthenticationResult.IdToken == "" ||
		*authOutput.AuthenticationResult.AccessToken == "" ||
		*authOutput.AuthenticationResult.RefreshToken == "" ||
		*authOutput.AuthenticationResult.ExpiresIn == 0 {
		return nil, fmt.Errorf("token is nil")
	}

	return &UserToken{
		AccessToken:  *authOutput.AuthenticationResult.AccessToken,
		IDToken:      *authOutput.AuthenticationResult.IdToken,
		RefreshToken: *authOutput.AuthenticationResult.RefreshToken,
		Expiration:   time.Now().Add(time.Duration(*authOutput.AuthenticationResult.ExpiresIn) * time.Second),
	}, nil
}

func (c *cognitoClient) refreshTokenAuth(username, refreshToken string) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	authFlow := "REFRESH_TOKEN_AUTH"

	authInputParams := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String(authFlow),
		AuthParameters: map[string]*string{
			"REFRESH_TOKEN": aws.String(refreshToken),
			"SECRET_HASH":   aws.String(convertSecretHash(username, c.clientID, c.clientSecret)),
		},
		ClientId: aws.String(c.clientID),
	}
	authOutput, err := c.provider.InitiateAuth(authInputParams)
	if err != nil {
		return nil, fmt.Errorf("admin initiate auth error: %v", err)
	}

	return authOutput, nil
}

// Base64 ( HMAC_SHA256 ( "Client Secret Key", "Username" + "Client Id" ) )
func convertSecretHash(username, clientID, clientSecret string) string {
	key := clientSecret
	data := username + clientID

	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	base64Encoded := base64.StdEncoding.EncodeToString(hashed)

	return base64Encoded
}
