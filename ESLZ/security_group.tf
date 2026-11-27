terraform {
  required_version = ">= 1.9"
}

variable "security_groups" {
  description = "Security groups to deploy, keyed by name"
  type        = any
  default     = {}
}

variable "vpc_ids" {
  description = "Map of VPC key to its ID, e.g. { for k, v in module.vpc : k => v.id }. An entry picks one with vpc_key."
  type        = map(string)
  default     = {}
}

variable "prefix_list_ids" {
  description = "Map of prefix list key to its ID, e.g. { for k, v in module.vpc_endpoint : k => v.prefix_list_id }. A rule picks one with prefix_list_key."
  type        = map(string)
  default     = {}
}

variable "security_group_ids" {
  description = "Map of security group key to its ID, for the groups made elsewhere, e.g. { for k, v in module.other_security_group : k => v.id }. A rule picks one with referenced_security_group_key. Never the map of this module itself: a module that reads its own outputs waits for itself (a cycle)."
  type        = map(string)
  default     = {}
}

module "security_group" {
  source   = "github.com/canada-ca-terraform-modules/terraform-aws-caf-security_group.git?ref=v1.0.0"
  for_each = var.security_groups

  userDefinedString  = each.key
  env                = var.env
  vpc_ids            = var.vpc_ids
  prefix_list_ids    = var.prefix_list_ids
  security_group_ids = var.security_group_ids
  security_group     = each.value
  tags               = var.tags
}
