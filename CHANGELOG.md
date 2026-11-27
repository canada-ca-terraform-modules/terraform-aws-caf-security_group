# Changelog

All notable changes to this module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This file must be updated as part of every change to this module.

## [Unreleased]

### Changed

- The README, the tfvars example, the comments and the tests describe a generic appliance, with no product, design document or task named. No behaviour changes. The README example no longer names the GWLB subnets.

## [1.0.0]

### Added

- Initial release: one `aws_security_group` per module instance, declared with a single `security_group = each.value`.
- Typical use: the three groups of a network appliance with several interfaces (management, private, public).
- The VPC is required: a literal `vpc_id`, or a `vpc_key` resolved through the `vpc_ids` lookup map. A group with neither, or with
  a key not in the map, fails the plan.
- Standalone rules, one resource per entry: `ingress_rules` (`aws_vpc_security_group_ingress_rule`) and `egress_rules`
  (`aws_vpc_security_group_egress_rule`).
- A rule has exactly one source: `cidr_ipv4`, `cidr_ipv6`, a prefix list, a security group, or `self = true`.
- A prefix list is a literal `prefix_list_id` or a `prefix_list_key` of the `prefix_list_ids` lookup map.
- A security group is a literal `referenced_security_group_id` or a `referenced_security_group_key` of the `security_group_ids` lookup
  map. The map holds groups made by another module block; a module block cannot read its own groups (a cycle).
- Each rule is checked before it is planned, and the plan fails naming the rule and every problem: a key the module does not read, a
  missing or unknown `ip_protocol` (`tcp`, `udp`, `icmp`, `icmpv6`, a number from 0 to 255, or `-1`), the ports of the protocol, and
  the source.
- Ports: none with `-1`; `from_port` and `to_port` required with `tcp`, `udp` and `icmp`, both or neither with `icmpv6`; 0 to 65535 and
  not backwards for `tcp` and `udp`; -1 to 255 for the type and code of `icmp` and `icmpv6`.
- A `prefix_list_key` or `referenced_security_group_key` that is not in its lookup map fails the plan.
- `allow_all_egress` adds the all-protocol egress rule the provider removes from a new group. An `egress_rules` entry named
  `allow-all-egress` beside it fails the plan, since it would replace the generated rule.
- `rules_exclusive` (`aws_vpc_security_group_rules_exclusive`) makes the standalone rules the only rules of the group.
- `vpc_associations` (`aws_vpc_security_group_vpc_association`) associates the group with other VPCs.
- `inline_ingress_rules` and `inline_egress_rules`, the legacy inline rules of `aws_security_group`. They fail the plan beside
  `ingress_rules`, `egress_rules`, `allow_all_egress` or `rules_exclusive`.
- A key the module does not read fails the plan, on the object, an inline rule, `rules_exclusive` and an association, so a typo is not
  ignored.
- `description` defaults to `Managed by Terraform` and must be 1 to 255 characters (AWS also limits its characters; the module does not
  check them).
- Outputs `id`, `arn`, `name`, `vpc_id`, `owner_id`, `object` and the rule IDs by key.
- The name is `<env>-<userDefinedString>-sg` (the suffix is in `Documentation/Standards/AWS-Naming-and-Tagging-Suffixes.md`): letters,
  digits and hyphens with the case kept, at most 255 characters, never starting with `sg-` (a base of `sg` becomes `sg0`).
- A custom `name` keeps the characters AWS allows in a group name. The Name tag drops the characters a tag value does not allow.
- The Name tag of a rule is `<group>-in-<key>` or `-out-<key>`, at most 256 characters.
- Provider `~> 6.68`, tested against `6.71.0`. `scripts/coverage_check.sh` reports nothing for the `aws_vpc_security_group` prefix and only
  `aws_security_group_rule` for the `aws_security_group` prefix (excluded: the legacy rule, replaced by the two
  `aws_vpc_security_group_*_rule` resources).
- Test runs cover each feature (present and absent), the three appliance groups, each rejection beside an accepting run, and the naming
  boundaries the runs pin.
