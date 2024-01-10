package repository

import "github.com/katsuokaisao/cognito-s3-access-study/domain"

type CognitoClient interface {
	GetUserToken(username, password string) (*domain.UserToken, error)
	GetCredentials(idToken string) (*domain.Credential, error)
}

type S3Client interface {
	HeadBucket(bucket string) error
	DownloadObject(bucket, key string) (string, error)
}
