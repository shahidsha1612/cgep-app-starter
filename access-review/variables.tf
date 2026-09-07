variable "aws_region" {
  type        = string
  description = "AWS region to deploy the access review into."
  default     = "us-east-1"
}

variable "schedule_expression" {
  type        = string
  description = "How often EventBridge triggers the review (rate() or cron())."
  default     = "rate(30 days)"
}

variable "recipient_email" {
  type        = string
  description = "SES-verified address that receives the report email. Leave empty to skip email."
  default     = ""
}

variable "sender_email" {
  type        = string
  description = "SES-verified From address. Defaults to recipient_email when empty."
  default     = ""
}

variable "enable_email" {
  type        = bool
  description = "Send the report by email via SES. Requires verified identities (SES sandbox: both from AND to must be verified)."
  default     = false
}

variable "enable_bedrock" {
  type        = bool
  description = "Generate an AI executive summary with Bedrock. Falls back to a plain text summary if disabled or unavailable."
  default     = true
}

variable "bedrock_model_id" {
  type        = string
  description = "Bedrock model or inference-profile ID for the narrative. Haiku 4.5 needs the us. inference-profile prefix."
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}
