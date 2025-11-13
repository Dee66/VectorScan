package main

import rego.v1

mandatory := ["CostCenter", "Project"]

encryption_disabled_msg(resource_type, name) := msg if {
  resource_type == "aws_db_instance"
  msg := sprintf(
    "P-SEC-001 VIOLATION: RDS instance '%s' has storage_encrypted set to false. Enable encryption with storage_encrypted = true and provide kms_key_id",
    [name],
  )
}

encryption_disabled_msg(resource_type, name) := msg if {
  resource_type == "aws_rds_cluster"
  msg := sprintf(
    "P-SEC-001 VIOLATION: RDS cluster '%s' has storage_encrypted set to false. Enable encryption with storage_encrypted = true and provide kms_key_id",
    [name],
  )
}

missing_kms_msg(resource_type, name) := sprintf(
  "P-SEC-001 VIOLATION: %s '%s' has encryption enabled but no kms_key_id specified. Provide a valid KMS key for proper key management",
  [resource_type, name],
)

missing_tag_msg(resource_type, name, tag) := sprintf(
  "P-FIN-001 VIOLATION: %s '%s' missing mandatory tag '%s'. Required tags: %v",
  [resource_type, name, tag, mandatory],
)

empty_tag_msg(resource_type, name, tag) := sprintf(
  "P-FIN-001 VIOLATION: %s '%s' has empty value for mandatory tag '%s'. Provide meaningful tag values for cost attribution",
  [resource_type, name, tag],
)

no_tags_msg(resource_type, name) := sprintf(
  "P-FIN-001 VIOLATION: %s '%s' has no tags. All resources must include tags: %v",
  [resource_type, name, mandatory],
)

test_encryption_and_tags_pass if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_db_instance",
            "name": "aws_db_instance.good",
            "values": {
              "storage_encrypted": true,
              "kms_key_id": "kms123",
              "tags": {"CostCenter": "ai-platform", "Project": "rag"}
            }
          },
          {
            "type": "aws_rds_cluster",
            "name": "aws_rds_cluster.good",
            "values": {
              "storage_encrypted": true,
              "kms_key_id": "kms456",
              "tags": {"CostCenter": "ai-platform", "Project": "rag"}
            }
          }
        ]
      }
    }
  }
  count(denies) == 0
}

test_missing_encryption_fails if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_db_instance",
            "name": "aws_db_instance.bad",
            "values": {
              "storage_encrypted": false,
              "tags": {"CostCenter": "ai-platform", "Project": "rag"}
            }
          }
        ]
      }
    }
  }
  denies[_] == encryption_disabled_msg("aws_db_instance", "aws_db_instance.bad")
}

test_missing_kms_key_fails if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_db_instance",
            "name": "aws_db_instance.nokms",
            "values": {
              "storage_encrypted": true,
              "tags": {"CostCenter": "ai-platform", "Project": "rag"}
            }
          }
        ]
      }
    }
  }
  denies[_] == missing_kms_msg("aws_db_instance", "aws_db_instance.nokms")
}

test_missing_project_tag_fails if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_db_instance",
            "name": "aws_db_instance.notag",
            "values": {
              "storage_encrypted": true,
              "kms_key_id": "kms123",
              "tags": {"CostCenter": "ai-platform"}
            }
          }
        ]
      }
    }
  }
  denies[_] == missing_tag_msg("aws_db_instance", "aws_db_instance.notag", "Project")
}

test_empty_costcenter_tag_fails if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_db_instance",
            "name": "aws_db_instance.emptytag",
            "values": {
              "storage_encrypted": true,
              "kms_key_id": "kms123",
              "tags": {"CostCenter": " ", "Project": "rag"}
            }
          }
        ]
      }
    }
  }
  denies[_] == empty_tag_msg("aws_db_instance", "aws_db_instance.emptytag", "CostCenter")
}

test_cluster_missing_encryption_fails if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_rds_cluster",
            "name": "aws_rds_cluster.bad",
            "values": {
              "storage_encrypted": false,
              "tags": {"CostCenter": "finops", "Project": "rag"}
            }
          }
        ]
      }
    }
  }
  denies[_] == encryption_disabled_msg("aws_rds_cluster", "aws_rds_cluster.bad")
}

test_cluster_missing_kms_key_fails if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_rds_cluster",
            "name": "aws_rds_cluster.nokms",
            "values": {
              "storage_encrypted": true,
              "tags": {"CostCenter": "finops", "Project": "rag"}
            }
          }
        ]
      }
    }
  }
  denies[_] == missing_kms_msg("aws_rds_cluster", "aws_rds_cluster.nokms")
}

test_missing_tags_object_fails if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_db_instance",
            "name": "aws_db_instance.notags",
            "values": {
              "storage_encrypted": true,
              "kms_key_id": "kms123"
            }
          }
        ]
      }
    }
  }
  denies[_] == no_tags_msg("aws_db_instance", "aws_db_instance.notags")
}

test_resource_changes_shape_supported if {
  denies := data.free_policies.deny with input as {
    "resource_changes": [
      {
        "type": "aws_db_instance",
        "name": "plan.db",
        "change": {
          "after": {
            "storage_encrypted": true,
            "kms_key_id": "kms123",
            "tags": {"CostCenter": "ai", "Project": "rag"}
          }
        }
      },
      {
        "type": "aws_db_instance",
        "name": "plan.db2",
        "change": {
          "after": {
            "storage_encrypted": true,
            "tags": {"CostCenter": "ai", "Project": "rag"}
          }
        }
      }
    ]
  }
  denies[_] == missing_kms_msg("aws_db_instance", "plan.db2")
}

test_multiple_violations_reported if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_db_instance",
            "name": "db.bad1",
            "values": {
              "storage_encrypted": false,
              "tags": {"CostCenter": "ai", "Project": "rag"}
            }
          },
          {
            "type": "aws_db_instance",
            "name": "db.bad2",
            "values": {
              "storage_encrypted": true,
              "tags": {"CostCenter": "ai"}
            }
          }
        ]
      }
    }
  }
  count(denies) == 3
  denies[_] == encryption_disabled_msg("aws_db_instance", "db.bad1")
  denies[_] == missing_tag_msg("aws_db_instance", "db.bad2", "Project")
  denies[_] == missing_kms_msg("aws_db_instance", "db.bad2")
}

test_cluster_missing_tags_fails if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_rds_cluster",
            "name": "cluster.notags",
            "values": {
              "storage_encrypted": true,
              "kms_key_id": "kms-1"
            }
          }
        ]
      }
    }
  }
  denies[_] == no_tags_msg("aws_rds_cluster", "cluster.notags")
}

test_tags_object_present_but_empty_fails if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_db_instance",
            "name": "db.emptytags",
            "values": {
              "storage_encrypted": true,
              "kms_key_id": "kms",
              "tags": {}
            }
          }
        ]
      }
    }
  }
  count(denies) == 2
  denies[_] == missing_tag_msg("aws_db_instance", "db.emptytags", "CostCenter")
  denies[_] == missing_tag_msg("aws_db_instance", "db.emptytags", "Project")
}

test_resource_changes_cluster_missing_kms if {
  denies := data.free_policies.deny with input as {
    "resource_changes": [
      {
        "type": "aws_rds_cluster",
        "name": "plan.cluster",
        "change": {
          "after": {
            "storage_encrypted": true,
            "tags": {"CostCenter": "ai", "Project": "rag"}
          }
        }
      }
    ]
  }
  denies[_] == missing_kms_msg("aws_rds_cluster", "plan.cluster")
}

test_resource_with_custom_tags_pass if {
  denies := data.free_policies.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "type": "aws_db_instance",
            "name": "db.customtags",
            "values": {
              "storage_encrypted": true,
              "kms_key_id": "kms",
              "tags": {"CostCenter": "ai", "Project": "rag", "Owner": "data"}
            }
          }
        ]
      }
    }
  }
  count(denies) == 0
}