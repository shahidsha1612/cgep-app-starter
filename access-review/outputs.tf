output "report_bucket" {
  value       = aws_s3_bucket.reports.id
  description = "S3 bucket where access-review CSV reports are written."
}

output "lambda_function_name" {
  value       = aws_lambda_function.access_review.function_name
  description = "Name of the access-review Lambda (use with run_report / aws lambda invoke)."
}

output "schedule_rule" {
  value       = aws_cloudwatch_event_rule.schedule.name
  description = "EventBridge rule driving the scheduled review."
}

output "log_group" {
  value       = aws_cloudwatch_log_group.lambda.name
  description = "CloudWatch log group for the Lambda."
}
