// Terraform test for vector-db-aws module (scaffolding)

mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:us-east-1:123456789012:key/mock"
      key_id = "mock-kms-key-id"
    }
  }

  mock_resource "aws_kms_alias" {
    defaults = {
      id   = "alias/testvd-vector-db"
      name = "alias/testvd-vector-db"
    }
  }

  mock_resource "aws_db_subnet_group" {
    defaults = {
      arn  = "arn:aws:rds:us-east-1:123456789012:subgrp:testvd"
      name = "testvd-vector-db-subnet-group"
    }
  }

  mock_resource "aws_security_group" {
    defaults = {
      id  = "sg-1234567890abcdef0"
      arn = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1234567890abcdef0"
    }
  }

  mock_resource "aws_db_instance" {
    defaults = {
      id                        = "testvd-vector-db"
      arn                       = "arn:aws:rds:us-east-1:123456789012:db:testvd"
      endpoint                  = "testvd.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com"
      address                   = "testvd.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com"
      port                      = 5432
      db_name                   = "vectordb"
      username                  = "dbadmin"
      backup_retention_period   = 7
      backup_window             = "03:00-04:00"
      maintenance_window        = "sun:04:00-sun:05:00"
      availability_zone         = "us-east-1a"
      tags_all                  = { CostCenter = "ai-platform", Project = "rag-system" }
      kms_key_id                = "arn:aws:kms:us-east-1:123456789012:key/mock"
      enabled_cloudwatch_logs_exports = ["postgresql"]
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn  = "arn:aws:iam::123456789012:role/testvd-monitoring"
      name = "testvd-monitoring-role"
    }
  }

  mock_resource "aws_iam_role_policy_attachment" {
    defaults = {
      id = "testvd-monitoring-attachment"
    }
  }
}


run "vector_db_defaults" {
  command = apply
  module {
    source = "../../modules/vector-db-aws"
  }

  variables {
    name_prefix     = "testvd"
    vpc_id          = "vpc-12345678"
    subnet_ids      = ["subnet-11111111", "subnet-22222222"]
    master_password = "Password123!"
    tags = {
      CostCenter = "ai-platform"
      Project    = "rag-system"
    }
  }

  // Basic output assertions
  assert {
    condition     = output.db_port == 5432
    error_message = "Expected Postgres port 5432 by default"
  }

  assert {
    condition     = can(output.kms_key_arn) && length(tostring(output.kms_key_arn)) > 0
    error_message = "KMS key ARN should be set for encryption"
  }
}
