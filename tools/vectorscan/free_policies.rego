package main

import rego.v1

# Minimal policies for the VectorScan lead magnet covering:
# - P-SEC-001: Encryption mandate for RDS/pgvector
# - P-FIN-001: Mandatory cost allocation tags

required_tags := ["CostCenter", "Project"]

deny contains msg if {
  rc := resource_changes[_]
  rc.type == "aws_db_instance"
  after := resource_after(rc)
  not storage_encrypted_enabled(after)
  msg := sprintf("P-SEC-001: %s has storage_encrypted != true", [resource_label(rc)])
}

deny contains msg if {
  rc := resource_changes[_]
  rc.type == "aws_rds_cluster"
  after := resource_after(rc)
  not storage_encrypted_enabled(after)
  msg := sprintf("P-SEC-001: %s has storage_encrypted != true", [resource_label(rc)])
}

deny contains msg if {
  rc := resource_changes[_]
  rc.type == "aws_db_instance"
  after := resource_after(rc)
  storage_encrypted_enabled(after)
  not has_nonempty_kms(after)
  msg := sprintf("P-SEC-001: %s encryption enabled but kms_key_id is missing/empty", [resource_label(rc)])
}

deny contains msg if {
  rc := resource_changes[_]
  rc.type == "aws_rds_cluster"
  after := resource_after(rc)
  storage_encrypted_enabled(after)
  not has_nonempty_kms(after)
  msg := sprintf("P-SEC-001: %s encryption enabled but kms_key_id is missing/empty", [resource_label(rc)])
}

deny contains msg if {
  rc := resource_changes[_]
  after := resource_after(rc)
  tags := object.get(after, "tags", null)
  is_object(tags)
  required_tag := required_tags[_]
  not tag_present(tags, required_tag)
  msg := sprintf("P-FIN-001: %s missing/empty tag '%s'", [resource_label(rc), required_tag])
}

deny contains msg if {
  rc := resource_changes[_]
  after := resource_after(rc)
  tags := object.get(after, "tags", null)
  not is_object(tags)
  msg := sprintf("P-FIN-001: %s has no tags object defined", [resource_label(rc)])
}

storage_encrypted_enabled(after) if {
  after.storage_encrypted == true
}

has_nonempty_kms(after) if {
  nonempty_string(after.kms_key_id)
}

nonempty_string(value) if {
  is_string(value)
  regex.match(".*\\S.*", value)
}

tag_present(tags, key) if {
  nonempty_string(tags[key])
}

resource_label(rc) := rc.address if {
  rc.address
} else := rc.name if {
  rc.name
} else := "resource" if {
  true
}

resource_after(rc) := rc.change.after if {
  rc.change
  rc.change.after
} else := rc.values if {
  rc.values
}

resource_changes contains rc if {
  rc := input.resource_changes[_]
}

resource_changes contains rc if {
  root := input.planned_values.root_module
  root.resources
  rc := root.resources[_]
}
