// Terraform tests for iam-agent-role module

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:root"
      user_id    = "AIDACKCEVSQ6C2EXAMPLE"
    }
  }

  mock_data "aws_region" {
    defaults = {
      id   = "us-east-1"
      name = "us-east-1"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn                  = "arn:aws:iam::123456789012:role/testiam-agent"
      name                 = "testiam-agent-role"
      unique_id            = "testiam-agent-role-uid"
      max_session_duration = 3600
      assume_role_policy   = "{}"
    }
  }

  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::123456789012:policy/testiam"
      id  = "testiam-policy-id"
    }
  }

  mock_resource "aws_iam_role_policy_attachment" {
    defaults = {
      id = "testiam-attachment-id"
    }
  }
}

run "iam_role_with_s3_and_logs" {
  command = apply
  module {
    source = "../../modules/iam-agent-role"
  }

  variables {
    name_prefix         = "testiam"
    s3_bucket_arns      = ["arn:aws:s3:::example-bucket"]
    s3_object_arns      = ["arn:aws:s3:::example-bucket/vector-data.json"]
    enable_cloudwatch_logs = true
    vector_db_arn          = "arn:aws:rds:us-east-1:123456789012:db:vector-test"

    // Required FinOps tags
    tags = {
      CostCenter = "ai-platform"
      Project    = "rag-system"
    }
  }

  assert {
    condition     = can(output.role_name) && length(tostring(output.role_name)) > 0
    error_message = "IAM role name should be set"
  }

  assert {
    condition     = can(output.explicit_denies_policy_arn) && output.explicit_denies_policy_arn != null
    error_message = "Explicit denies policy ARN should be set"
  }

  assert {
    condition     = can(output.s3_read_policy_arn) && output.s3_read_policy_arn != null
    error_message = "S3 read policy ARN should be set when s3_bucket_arns is provided"
  }

  assert {
    condition     = can(output.resource_tags) && contains(keys(output.resource_tags), "CostCenter") && contains(keys(output.resource_tags), "Project")
    error_message = "Tags should include CostCenter and Project"
  }

  assert {
    condition     = output.vector_db_access_scope == "arn:aws:rds:us-east-1:123456789012:db:vector-test"
    error_message = "Vector DB access scope should match the provided ARN"
  }
}
