fixpack_id = "P-VEC-003"

description = "Restrict network CIDRs from 0.0.0.0/0."

terraform_patch = <<EOT
allowed_cidrs = ["10.0.0.0/16"]
EOT
