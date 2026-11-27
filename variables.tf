variable "tags" {
  description = "Tags applied to all resources that take tags (merged with security_group.tags)"
  type        = map(string)
  default     = {}
}

variable "env" {
  description = "(Required) env value used in name generation"
  type        = string
}

variable "userDefinedString" {
  description = "(Required) UserDefinedString part of the name of the security group"
  type        = string
}

variable "vpc_ids" {
  description = "Optional map of VPC key to its ID. Resolves security_group.vpc_key and the vpc_key of security_group.vpc_associations. e.g. { for k, v in module.vpc : k => v.id }"
  type        = map(string)
  default     = {}
}

variable "security_group_ids" {
  description = "Optional map of security group key to its ID. Resolves the referenced_security_group_key of the rules. e.g. { for k, v in module.other_security_group : k => v.id }. Never the groups of the module block itself: a module that reads its own outputs waits for itself (a cycle)."
  type        = map(string)
  default     = {}
}

variable "prefix_list_ids" {
  description = "Optional map of prefix list key to its ID. Resolves the prefix_list_key of the rules. e.g. { for k, v in module.vpc_endpoint : k => v.prefix_list_id }"
  type        = map(string)
  default     = {}
}

variable "security_group" {
  description = "(Required) Object describing the security group and its rules (see TFVars Parameters in the README). Optional `name` key overrides the auto-derived \"<env>-<userDefinedString>-sg\" name."
  type        = any
  default     = {}
}
