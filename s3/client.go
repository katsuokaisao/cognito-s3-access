package s3

import (
	"bytes"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type S3Client interface {
	HeadBucket(bucket string) error
	DownloadObject(bucket, key string) (string, error)
}

type s3Client struct {
	downloader *s3manager.Downloader
}

func NewS3Client(id, secret, token string) S3Client {
	sess := session.Must(session.NewSession(
		&aws.Config{
			Credentials: credentials.NewStaticCredentials(
				id,
				secret,
				token,
			),
		},
	))
	downloader := s3manager.NewDownloader(sess)

	return &s3Client{
		downloader: downloader,
	}
}

// HeadBucket は接続確認のためのメソッドです。
func (c *s3Client) HeadBucket(bucket string) error {
	_, err := c.downloader.S3.HeadBucket(&s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	return err
}

func (c *s3Client) DownloadObject(bucket, key string) (string, error) {
	buf := aws.NewWriteAtBuffer([]byte{})
	_, err := c.downloader.Download(buf, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", err
	}

	data := bytes.NewBuffer(buf.Bytes()).String()
	return data, nil
}
