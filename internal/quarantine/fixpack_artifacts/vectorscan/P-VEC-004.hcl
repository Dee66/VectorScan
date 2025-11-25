fixpack_id = "P-VEC-004"

description = "Increase vector dimension to recommended minimum."

terraform_patch = <<EOT
dimension = 32
EOT
