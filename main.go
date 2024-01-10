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
	userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	idPoolID := os.Getenv("COGNITO_ID_POOL_ID")
	clientID := os.Getenv("COGNITO_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_CLIENT_SECRET")

	username := os.Getenv("COGNITO_USERNAME")
	password := os.Getenv("COGNITO_PASSWORD")

	bucket := os.Getenv("S3_BUCKET")
	objectKey := os.Getenv("S3_OBJECT_KEY")

	client := cognito.NewCognitoClient(region, accountID, userPoolID, idPoolID, clientID, clientSecret)
	userToken, err := client.GetUserToken(username, password)
	if err != nil {
		panic(err)
	}
	fmt.Println("get user token success")

	credential, err := client.GetCredentials(userToken.IDToken)
	if err != nil {
		panic(err)
	}
	fmt.Println("get credential success")

	s3Client := s3.NewS3Client(credential.AccessKeyID, credential.SecretKey, credential.SessionToken, region)
	if err = s3Client.HeadBucket(bucket); err != nil {
		panic(fmt.Errorf("head bucket error: %v", err))
	}
	fmt.Println("head bucket success")

	data, err := s3Client.DownloadObject(bucket, objectKey)
	if err != nil {
		panic(fmt.Errorf("download object error: %v", err))
	}

	fmt.Printf("s3 data: %s\n", data)
}
