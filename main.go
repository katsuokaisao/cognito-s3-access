package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/katsuokaisao/cognito-s3-access-study/cognito"
	"github.com/katsuokaisao/cognito-s3-access-study/s3"
)

func main() {
	if err := godotenv.Load(".env"); err != nil {
		panic("読み込み出来ませんでした")
	}

	region := os.Getenv("COGNITO_REGION")
	accountID := os.Getenv("COGNITO_ACCOUNT_ID")
	poolID := os.Getenv("COGNITO_POOL_ID")
	clientID := os.Getenv("COGNITO_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_CLIENT_SECRET")

	username := os.Getenv("COGNITO_USERNAME")
	password := os.Getenv("COGNITO_PASSWORD")

	bucket := os.Getenv("S3_BUCKET")
	objectKey := os.Getenv("S3_OBJECT_KEY")

	client := cognito.NewCognitoClient(region, accountID, poolID, clientID, clientSecret)
	userToken, err := client.GetUserToken(username, password)
	if err != nil {
		panic(err)
	}

	credential, err := client.GetCredentials(userToken.IDToken)
	if err != nil {
		panic(err)
	}

	s3Client := s3.NewS3Client(credential.AccessKeyID, credential.SecretKey, credential.SessionToken)
	if err = s3Client.HeadBucket(bucket); err != nil {
		panic(err)
	}

	data, err := s3Client.DownloadObject(bucket, objectKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("s3 data: %s\n", data)
}
