fixpack_id = "P-VEC-001"

description = "Disable public access on vector index."

terraform_patch = <<EOT
# Example: remove public access
public_access = false
EOT
