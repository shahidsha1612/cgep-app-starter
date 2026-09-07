######################################################################
# Acme Health — Automated Access Review (CGE-P Capstone GRC control)
#
# A scheduled Lambda that audits THIS AWS account for common IAM / S3
# security gaps (MFA, stale access keys, public buckets, weak password
# policy, root usage), writes a timestamped CSV to an S3 report bucket,
# asks Bedrock for a plain-English executive summary, and (optionally)
# emails the summary via SES.
#
# Deployed into YOUR account (the one your AWS creds point at). It uses
# LOCAL Terraform state on purpose — it is independent of the Acme Health
# workload and its remote S3 backend, so it needs no cross-account access.
######################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # Local state (terraform.tfstate in this dir). No backend block.
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-access-review"
      ManagedBy = "terraform"
      Component = "grc-access-review"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "access-review"
  suffix      = random_id.suffix.hex
  account_id  = data.aws_caller_identity.current.account_id
}

######################################################################
# Report bucket — where each run's CSV lands. Kept deliberately
# compliant (encrypted, versioned, private) so the tool doesn't create
# the very findings it reports on.
######################################################################

resource "aws_s3_bucket" "reports" {
  bucket = "${local.name_prefix}-reports-${local.account_id}-${local.suffix}"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# Lambda execution role
#   - AWSLambdaBasicExecutionRole : CloudWatch Logs
#   - SecurityAudit               : read-only access to security config
#                                   across IAM, S3, etc.
#   - inline                      : credential report, write report,
#                                   invoke Bedrock, send SES email
######################################################################

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.name_prefix}-lambda-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

data "aws_iam_policy_document" "inline" {
  statement {
    sid       = "WriteReports"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/*"]
  }

  # SecurityAudit can READ a credential report but not GENERATE one.
  statement {
    sid = "CredentialReport"
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
      "iam:GetAccountSummary",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "InvokeBedrock"
    actions   = ["bedrock:InvokeModel"]
    resources = ["*"]
  }

  statement {
    sid       = "SendEmail"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "inline" {
  name   = "${local.name_prefix}-inline-${local.suffix}"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.inline.json
}

######################################################################
# Lambda function
######################################################################

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/index.py"
  output_path = "${path.module}/build/access-review.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}-${local.suffix}"
  retention_in_days = 30
}

resource "aws_lambda_function" "access_review" {
  function_name    = "${local.name_prefix}-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      REPORT_BUCKET    = aws_s3_bucket.reports.id
      RECIPIENT_EMAIL  = var.recipient_email
      SENDER_EMAIL     = var.sender_email == "" ? var.recipient_email : var.sender_email
      BEDROCK_MODEL_ID = var.bedrock_model_id
      ENABLE_EMAIL     = tostring(var.enable_email)
      ENABLE_BEDROCK   = tostring(var.enable_bedrock)
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

######################################################################
# EventBridge schedule — triggers the Lambda on a cadence
######################################################################

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.name_prefix}-schedule-${local.suffix}"
  description         = "Triggers the automated access review on a schedule"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.access_review.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.access_review.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
