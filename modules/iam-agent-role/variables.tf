variable "name_prefix" { type = string }
variable "s3_bucket_arns" { type = list(string) }
variable "s3_object_arns" { type = list(string) }
variable "enable_cloudwatch_logs" { type = bool }
variable "vector_db_arn" { type = string }
variable "tags" { type = map(string) }
