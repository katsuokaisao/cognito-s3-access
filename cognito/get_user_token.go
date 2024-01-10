package cognito

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

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

	userToken, err := c.getUserPasswordAuth(username, password)
	if err != nil {
		return nil, err
	}
	if userToken == nil {
		return nil, fmt.Errorf("cat not fetch token")
	}

	c.setUserToken(username, userToken)

	return userToken, nil
}

func (c *cognitoClient) getUserPasswordAuth(username, password string) (*UserToken, error) {
	authOutput, err := c.userPasswordAuth(username, password)
	if err != nil {
		return nil, fmt.Errorf("user srp auth error: %v", err)
	}

	if authOutput.ChallengeName == nil {
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

	if *authOutput.ChallengeName != "NEW_PASSWORD_REQUIRED" {
		return nil, fmt.Errorf("unexpected challenge name: %v", *authOutput.ChallengeName)
	}

	challengeOutPut, err := c.respondToAuthChallenge(
		authOutput.ChallengeName,
		map[string]*string{
			"USERNAME":     aws.String(username),
			"NEW_PASSWORD": aws.String(password),
			"SECRET_HASH":  aws.String(convertSecretHash(username, c.clientID, c.clientSecret)),
		},
		authOutput.Session,
	)
	if err != nil {
		return nil, fmt.Errorf("respond to auth challenge error: %v", err)
	}
	if challengeOutPut.ChallengeName != nil {
		return nil, fmt.Errorf("unexpected next challenge: %v", *challengeOutPut.ChallengeName)
	}

	if challengeOutPut.AuthenticationResult == nil ||
		*challengeOutPut.AuthenticationResult.IdToken == "" ||
		*challengeOutPut.AuthenticationResult.AccessToken == "" ||
		*challengeOutPut.AuthenticationResult.RefreshToken == "" ||
		*challengeOutPut.AuthenticationResult.ExpiresIn == 0 {
		return nil, fmt.Errorf("challenge success but token is nil")
	}

	return &UserToken{
		AccessToken:  *challengeOutPut.AuthenticationResult.AccessToken,
		IDToken:      *challengeOutPut.AuthenticationResult.IdToken,
		RefreshToken: *challengeOutPut.AuthenticationResult.RefreshToken,
		Expiration:   time.Now().Add(time.Duration(*challengeOutPut.AuthenticationResult.ExpiresIn) * time.Second),
	}, nil
}

func (c *cognitoClient) getRefreshTokenAuth(username, refreshToken string) (*UserToken, error) {
	authOutput, err := c.refreshTokenAuth(username, refreshToken)
	if err != nil {
		return nil, err
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

// userSRPAuth USER_SRP_AUTHを選択した場合はPASSWORD_VERIFIERのチャレンジが必要で、PASSWORD_CLAIM_SIGNATUREを自前で計算する必要があり面倒なので今回は断念
// csrp.PasswordVerifierChallenge で計算できそうだったが、動作せずでした
// func (c *cognitoClient) userSRPAuth(username, password string) (*cognitoidentityprovider.InitiateAuthOutput, error) {
// 	authFlow := "USER_SRP_AUTH"

// 	csrp, err := cognitosrp.NewCognitoSRP(username, password, c.poolID, c.clientID, &c.clientSecret)
// 	if err != nil {
// 		return nil, fmt.Errorf("cognito srp error: %v", err)
// 	}

// 	return c.initiateAuth(authFlow, csrp.GetAuthParams())
// }

func (c *cognitoClient) userPasswordAuth(username, password string) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	authFlow := "USER_PASSWORD_AUTH"

	params := map[string]*string{
		"USERNAME":    aws.String(username),
		"PASSWORD":    aws.String(password),
		"SECRET_HASH": aws.String(convertSecretHash(username, c.clientID, c.clientSecret)),
	}

	return c.initiateAuth(authFlow, params)
}

func (c *cognitoClient) refreshTokenAuth(username, refreshToken string) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	authFlow := "REFRESH_TOKEN_AUTH"

	params := map[string]*string{
		"REFRESH_TOKEN": aws.String(refreshToken),
		"SECRET_HASH":   aws.String(convertSecretHash(username, c.clientID, c.clientSecret)),
	}

	return c.initiateAuth(authFlow, params)
}

func (c *cognitoClient) initiateAuth(authFlow string, authParameters map[string]*string) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	authInputParams := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       aws.String(authFlow),
		AuthParameters: authParameters,
		ClientId:       aws.String(c.clientID),
	}
	authOutput, err := c.provider.InitiateAuth(authInputParams)
	if err != nil {
		return nil, fmt.Errorf("initiate auth error: %v", err)
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

func (c *cognitoClient) respondToAuthChallenge(challengeName *string, challengeParameters map[string]*string, session *string) (*cognitoidentityprovider.RespondToAuthChallengeOutput, error) {

	resp, err := c.provider.RespondToAuthChallenge(
		&cognitoidentityprovider.RespondToAuthChallengeInput{
			ChallengeName:      challengeName,
			ChallengeResponses: challengeParameters,
			Session:            session,
			ClientId:           aws.String(c.clientID),
		},
	)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
