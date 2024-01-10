variable "cognito_identity_pool_id" {}
variable "bucket_name" {}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {}

resource "aws_iam_role" "cognito_auth_iam_role" {
  name = "cognito-auth-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Principal = {
          Federated = "cognito-identity.amazonaws.com"
        }
        Effect = "Allow"
        Condition = {
          StringEquals = {
            "cognito-identity.amazonaws.com:aud" = var.cognito_identity_pool_id
          }
          "ForAnyValue:StringLike" = {
            "cognito-identity.amazonaws.com:amr" = "authenticated"
          }
        }
      },
    ]
  })
}

resource "aws_iam_policy" "cognito_auth_iam_policy" {
  name = "cognito-auth-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "S3:GetObject",
        ]
        Effect   = "Allow"
        Resource = "arn:aws:s3:::${var.bucket_name}/*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cognito_auth_iam_role_policy_attachment" {
  role       = aws_iam_role.cognito_auth_iam_role.name
  policy_arn = aws_iam_policy.cognito_auth_iam_policy.arn
}

resource "aws_s3_bucket" "gtfs_rt_bucket" {
  bucket = var.bucket_name
}
