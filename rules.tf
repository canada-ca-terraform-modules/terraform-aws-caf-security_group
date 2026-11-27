## Standalone rules, one resource per rule (the provider takes one source per rule), and the exclusive rule set.
## A rule names exactly one source: cidr_ipv4, cidr_ipv6, a prefix list (prefix_list_id, or prefix_list_key in prefix_list_ids),
## a security group (referenced_security_group_id, or referenced_security_group_key in security_group_ids), or self = true
## (the group itself). A literal ID wins over its key. A rule is checked before it is planned (its keys, its protocol, its ports and
## its source) and the plan fails with the rule's name and every problem found. This module accepts the rules the caller sets: keeping the ingress rules
## of a destination within Documentation/Standards/Network-Security-Ingress-Authoritative-Segmentation.md is the caller's.
locals {
  ingress-rules = try(var.security_group.ingress_rules, {})
  egress-rules = merge(
    try(var.security_group.allow_all_egress, false) == true ? {
      allow-all-egress = { ip_protocol = "-1", cidr_ipv4 = "0.0.0.0/0", description = "Allow all outbound traffic" }
    } : {},
    try(var.security_group.egress_rules, {})
  )

  rule-keys = ["ip_protocol", "from_port", "to_port", "cidr_ipv4", "cidr_ipv6", "prefix_list_id", "prefix_list_key", "referenced_security_group_id", "referenced_security_group_key", "self", "description", "region", "tags"]
  # Port limits by protocol family: tcp and udp take ports, icmp and icmpv6 take a type and a code (-1 for all).
  port-min = { l4 = 0, icmp = -1, icmpv6 = -1 }
  port-max = { l4 = 65535, icmp = 255, icmpv6 = 255 }

  all-rules = merge(
    { for k, r in local.ingress-rules : "in|${k}" => r },
    { for k, r in local.egress-rules : "out|${k}" => r }
  )

  # What each rule says ("in|<key>" and "out|<key>"), read once so the checks below stay short.
  rule-parsed = {
    for k, r in local.all-rules : k => {
      unknown-keys = [for a in keys(r) : a if !contains(local.rule-keys, a)]
      protocol     = try(tostring(r.ip_protocol), null)
      from-given   = try(r.from_port, null) != null
      to-given     = try(r.to_port, null) != null
      from         = try(tonumber(r.from_port), null)
      to           = try(tonumber(r.to_port), null)
      sources = [
        for s in [
          try(r.cidr_ipv4, null),
          try(r.cidr_ipv6, null),
          try(coalesce(try(r.prefix_list_id, null), try(r.prefix_list_key, null)), null),
          try(coalesce(try(r.referenced_security_group_id, null), try(r.referenced_security_group_key, null)), null),
          try(r.self, false) == true ? "self" : null,
        ] : s if s != null
      ]
      prefix-key-unknown = try(r.prefix_list_id, null) == null && try(r.prefix_list_key, null) != null && !contains(keys(var.prefix_list_ids), try(r.prefix_list_key, ""))
      group-key-unknown  = try(r.referenced_security_group_id, null) == null && try(r.referenced_security_group_key, null) != null && !contains(keys(var.security_group_ids), try(r.referenced_security_group_key, ""))
    }
  }

  # l4 (tcp, udp), icmp, icmpv6, all (-1), other (a protocol number the provider takes without ports) or invalid.
  rule-class = {
    for k, p in local.rule-parsed : k => (
      p.protocol == null ? "invalid" :
      contains(["tcp", "udp", "6", "17"], p.protocol) ? "l4" :
      contains(["icmp", "1"], p.protocol) ? "icmp" :
      contains(["icmpv6", "58"], p.protocol) ? "icmpv6" :
      p.protocol == "-1" ? "all" :
      try(can(regex("^(0|[1-9][0-9]*)$", p.protocol)) && tonumber(p.protocol) <= 255, false) ? "other" : "invalid"
    )
  }

  # A rule with a problem fails the plan with every problem named; the lists are empty for a sound rule.
  rule-problems = {
    for k, p in local.rule-parsed : k => compact([
      length(p.unknown-keys) > 0 ? "unknown keys ${join(", ", p.unknown-keys)} (allowed: ${join(", ", local.rule-keys)})" : "",
      p.protocol == null ? "ip_protocol is required (tcp, udp, icmp, icmpv6, a protocol number from 0 to 255, or -1)" : "",
      p.protocol != null && local.rule-class[k] == "invalid" ? "ip_protocol \"${p.protocol}\" must be tcp, udp, icmp, icmpv6, a protocol number from 0 to 255, or -1" : "",
      length(p.sources) != 1 ? "needs exactly one source: cidr_ipv4, cidr_ipv6, prefix_list_id or prefix_list_key, referenced_security_group_id or referenced_security_group_key, or self = true (found ${length(p.sources)})" : "",
      p.prefix-key-unknown ? "prefix_list_key must be a key of prefix_list_ids (known: ${join(", ", keys(var.prefix_list_ids))}), or set prefix_list_id" : "",
      p.group-key-unknown ? "referenced_security_group_key must be a key of security_group_ids (known: ${join(", ", keys(var.security_group_ids))}), or set referenced_security_group_id" : "",
      local.rule-class[k] == "all" && (p.from-given || p.to-given) ? "ip_protocol -1 means every protocol and port, so from_port and to_port must not be set" : "",
      contains(["l4", "icmp"], local.rule-class[k]) && !(p.from-given && p.to-given) ? "ip_protocol ${p.protocol} needs from_port and to_port (the port range, or for icmp the type and the code, -1 for all)" : "",
      local.rule-class[k] == "icmpv6" && p.from-given != p.to-given ? "ip_protocol ${p.protocol} takes from_port and to_port (type and code) together, or neither" : "",
      contains(keys(local.port-min), local.rule-class[k]) && (
        (p.from-given && try(!(p.from >= local.port-min[local.rule-class[k]] && p.from <= local.port-max[local.rule-class[k]]), true)) ||
        (p.to-given && try(!(p.to >= local.port-min[local.rule-class[k]] && p.to <= local.port-max[local.rule-class[k]]), true))
      ) ? "from_port and to_port must be numbers from ${try(local.port-min[local.rule-class[k]], 0)} to ${try(local.port-max[local.rule-class[k]], 0)} for ip_protocol ${p.protocol}" : "",
      local.rule-class[k] == "l4" && try(p.from > p.to, false) ? "from_port (${p.from}) must not be greater than to_port (${p.to})" : "",
    ])
  }
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = local.ingress-rules

  security_group_id            = aws_security_group.this.id
  region                       = try(coalesce(try(each.value.region, null), local.region), null)
  ip_protocol                  = local.rule-parsed["in|${each.key}"].protocol
  from_port                    = try(each.value.from_port, null)
  to_port                      = try(each.value.to_port, null)
  cidr_ipv4                    = try(each.value.cidr_ipv4, null)
  cidr_ipv6                    = try(each.value.cidr_ipv6, null)
  prefix_list_id               = try(each.value.prefix_list_id, null) != null ? each.value.prefix_list_id : lookup(var.prefix_list_ids, try(each.value.prefix_list_key, ""), null)
  referenced_security_group_id = try(each.value.referenced_security_group_id, null) != null ? each.value.referenced_security_group_id : try(each.value.self, false) == true ? aws_security_group.this.id : lookup(var.security_group_ids, try(each.value.referenced_security_group_key, ""), null)
  description                  = try(each.value.description, null)
  tags                         = merge(var.tags, try(each.value.tags, {}), local.module_tag, { Name = local.ingress-rule-names[each.key] })

  lifecycle {
    precondition {
      condition     = length(local.rule-problems["in|${each.key}"]) == 0
      error_message = "ingress_rules[\"${each.key}\"]: ${join("; ", local.rule-problems["in|${each.key}"])}."
    }
  }
}

resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = local.egress-rules

  security_group_id            = aws_security_group.this.id
  region                       = try(coalesce(try(each.value.region, null), local.region), null)
  ip_protocol                  = local.rule-parsed["out|${each.key}"].protocol
  from_port                    = try(each.value.from_port, null)
  to_port                      = try(each.value.to_port, null)
  cidr_ipv4                    = try(each.value.cidr_ipv4, null)
  cidr_ipv6                    = try(each.value.cidr_ipv6, null)
  prefix_list_id               = try(each.value.prefix_list_id, null) != null ? each.value.prefix_list_id : lookup(var.prefix_list_ids, try(each.value.prefix_list_key, ""), null)
  referenced_security_group_id = try(each.value.referenced_security_group_id, null) != null ? each.value.referenced_security_group_id : try(each.value.self, false) == true ? aws_security_group.this.id : lookup(var.security_group_ids, try(each.value.referenced_security_group_key, ""), null)
  description                  = try(each.value.description, null)
  tags                         = merge(var.tags, try(each.value.tags, {}), local.module_tag, { Name = local.egress-rule-names[each.key] })

  lifecycle {
    precondition {
      condition     = length(local.rule-problems["out|${each.key}"]) == 0
      error_message = "egress_rules[\"${each.key}\"]: ${join("; ", local.rule-problems["out|${each.key}"])}."
    }
  }
}

# Makes the standalone rules above the only rules of the group: the provider removes any other rule found on it.
resource "aws_vpc_security_group_rules_exclusive" "this" {
  for_each = try(var.security_group.rules_exclusive, null) != null ? { enabled = true } : {}

  security_group_id = aws_security_group.this.id
  region            = try(coalesce(try(var.security_group.rules_exclusive.region, null), local.region), null)
  ingress_rule_ids  = toset([for r in aws_vpc_security_group_ingress_rule.this : r.id])
  egress_rule_ids   = toset([for r in aws_vpc_security_group_egress_rule.this : r.id])
}
