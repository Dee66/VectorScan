variable "name_prefix" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "master_password" { type = string }
variable "tags" { type = map(string) }
