package domain

import "time"

type UserToken struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	Expiration   time.Time
}

type Credential struct {
	AccessKeyID  string
	SecretKey    string
	SessionToken string
	Expiration   time.Time
}
