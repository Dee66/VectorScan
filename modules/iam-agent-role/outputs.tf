output "role_name" {
  value = aws_iam_role.this.name
}

output "explicit_denies_policy_arn" {
  value = aws_iam_policy.explicit_denies.arn
}

output "s3_read_policy_arn" {
  value = aws_iam_policy.s3_read.arn
}

output "resource_tags" {
  value = var.tags
}

output "vector_db_access_scope" {
  value = var.vector_db_arn
}
