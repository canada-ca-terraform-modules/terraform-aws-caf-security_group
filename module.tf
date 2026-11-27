## The core, always-created resource: the security group. Its standalone rules live in rules.tf (ingress and egress rules, the
## exclusive rule set) and the extra VPC associations in association.tf.
locals {
  region = try(var.security_group.region, null)

  # A literal VPC ID wins; otherwise the key resolves through vpc_ids. An unknown key is caught by a precondition.
  vpc-id-literal = try(coalesce(var.security_group.vpc_id), null)
  vpc-key        = try(coalesce(var.security_group.vpc_key), null)
  vpc-id         = local.vpc-id-literal != null ? local.vpc-id-literal : local.vpc-key != null ? lookup(var.vpc_ids, local.vpc-key, null) : null

  # The description is never defaulted silently when given: an empty one is rejected by the length check below.
  description = try(var.security_group.description, null) == null ? "Managed by Terraform" : var.security_group.description

  # Keys the object takes; a key outside these lists is a typo that would otherwise be ignored without a word.
  security-group-keys         = ["name", "description", "vpc_id", "vpc_key", "region", "revoke_rules_on_delete", "timeouts", "tags", "ingress_rules", "egress_rules", "allow_all_egress", "rules_exclusive", "vpc_associations", "inline_ingress_rules", "inline_egress_rules"]
  inline-rule-keys            = ["protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids", "security_groups", "self", "description"]
  unknown-security-group-keys = [for a in keys(var.security_group) : a if !contains(local.security-group-keys, a)]
  unknown-inline-rule-keys = distinct(flatten([
    for r in flatten([local.inline-ingress-rules, local.inline-egress-rules]) : [for a in keys(r) : a if !contains(local.inline-rule-keys, a)] if r != null
  ]))
  unknown-exclusive-keys = [for a in keys(try(var.security_group.rules_exclusive, {})) : a if a != "region"]

  # Inline rules (legacy): the provider wants every field of the object, so the missing ones are filled with its zero values.
  inline-ingress-rules = try(var.security_group.inline_ingress_rules, null)
  inline-egress-rules  = try(var.security_group.inline_egress_rules, null)
  inline-ingress = local.inline-ingress-rules == null ? null : [for r in local.inline-ingress-rules : {
    protocol         = r.protocol
    from_port        = try(r.from_port, 0)
    to_port          = try(r.to_port, 0)
    cidr_blocks      = try(tolist(r.cidr_blocks), [])
    ipv6_cidr_blocks = try(tolist(r.ipv6_cidr_blocks), [])
    prefix_list_ids  = try(tolist(r.prefix_list_ids), [])
    security_groups  = try(toset(r.security_groups), toset([]))
    self             = try(r.self, false)
    description      = try(r.description, "")
  }]
  inline-egress = local.inline-egress-rules == null ? null : [for r in local.inline-egress-rules : {
    protocol         = r.protocol
    from_port        = try(r.from_port, 0)
    to_port          = try(r.to_port, 0)
    cidr_blocks      = try(tolist(r.cidr_blocks), [])
    ipv6_cidr_blocks = try(tolist(r.ipv6_cidr_blocks), [])
    prefix_list_ids  = try(tolist(r.prefix_list_ids), [])
    security_groups  = try(toset(r.security_groups), toset([]))
    self             = try(r.self, false)
    description      = try(r.description, "")
  }]
}

resource "aws_security_group" "this" {
  name                   = local.sg-name
  description            = local.description
  vpc_id                 = local.vpc-id
  revoke_rules_on_delete = try(var.security_group.revoke_rules_on_delete, null)
  region                 = local.region
  ingress                = local.inline-ingress
  egress                 = local.inline-egress

  # Tags - Merging tags provided by ESLZ with tags provided by the user. Name is last so the naming standard wins.
  tags = merge(var.tags, try(var.security_group.tags, {}), local.module_tag, { Name = local.sg-tag-name })

  dynamic "timeouts" {
    for_each = try(var.security_group.timeouts, null) != null ? [var.security_group.timeouts] : []
    content {
      create = try(timeouts.value.create, null)
      delete = try(timeouts.value.delete, null)
    }
  }

  lifecycle {
    precondition {
      condition     = length(local.unknown-security-group-keys) == 0
      error_message = "security_group has unknown keys: ${join(", ", local.unknown-security-group-keys)} (allowed: ${join(", ", local.security-group-keys)})."
    }
    precondition {
      condition     = length(local.unknown-inline-rule-keys) == 0 && length(local.unknown-exclusive-keys) == 0
      error_message = "security_group.inline_ingress_rules, inline_egress_rules and rules_exclusive have unknown keys: ${join(", ", concat(local.unknown-inline-rule-keys, local.unknown-exclusive-keys))} (allowed for an inline rule: ${join(", ", local.inline-rule-keys)}; for rules_exclusive: region)."
    }
    precondition {
      condition     = local.vpc-id-literal != null || local.vpc-key != null
      error_message = "security_group needs a VPC: set vpc_id, or vpc_key present in vpc_ids."
    }
    precondition {
      condition     = local.vpc-id-literal != null || local.vpc-key == null || contains(keys(var.vpc_ids), local.vpc-key)
      error_message = "security_group.vpc_key must be a key of vpc_ids (known: ${join(", ", keys(var.vpc_ids))}), or set security_group.vpc_id."
    }
    # AWS: 1 to 255 characters, letters, digits, spaces and ._-:/()#,@[]+=&;{}!$* (not checked here).
    precondition {
      condition     = length(local.description) >= 1 && length(local.description) <= 255
      error_message = "security_group.description must be 1 to 255 characters (got ${length(local.description)})."
    }
    # The generated rule would be replaced by the caller's entry of the same key, and its meaning lost without a word.
    precondition {
      condition     = !(try(var.security_group.allow_all_egress, false) == true && contains(keys(try(var.security_group.egress_rules, {})), "allow-all-egress"))
      error_message = "security_group.egress_rules must not have the key allow-all-egress when allow_all_egress is true: it names the rule allow_all_egress generates. Rename the entry or drop allow_all_egress."
    }
    # The provider cannot manage a group's rules both inline and as standalone resources: the two fight over the set.
    precondition {
      condition = (local.inline-ingress == null && local.inline-egress == null) || (
        length(local.ingress-rules) + length(local.egress-rules) == 0 && try(var.security_group.rules_exclusive, null) == null
      )
      error_message = "security_group.inline_ingress_rules and inline_egress_rules cannot be combined with ingress_rules, egress_rules, allow_all_egress or rules_exclusive: use one way of managing the rules."
    }
  }
}
