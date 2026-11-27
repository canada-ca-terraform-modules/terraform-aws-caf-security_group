# terraform-aws-caf-security_group

CAF-compliant Terraform module for one AWS security group per module instance, with its standalone rules. Supports the whole `aws_security_group` and `aws_vpc_security_group_*` resource surface of aws provider `~> 6.68` (tested against `6.71.0`): the group, its ingress and egress rules (one `aws_vpc_security_group_ingress_rule` or `_egress_rule` each), the exclusive rule set and the association of the group with other VPCs. Typical use: the three security groups of a network appliance with several interfaces (management, private, public), and the groups of workloads.

See [Scope](#scope) below for the resources that are deliberately **not** part of this module.

## Usage

### ESLZ module block (`ESLZ/security_group.tf`)

```hcl
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
```

Config is always a map keyed by name. See [`ESLZ/security_group.tfvars`](ESLZ/security_group.tfvars) for the full set of `security_group` object parameters.

The lookup maps resolve foreign keys inside the module. Pass them straight from the modules that own the VPCs, the prefix lists and the other groups:

```hcl
vpc_ids            = { for k, v in module.vpc : k => v.id }
prefix_list_ids    = { for k, v in module.vpc_endpoint : k => v.prefix_list_id }
security_group_ids = { for k, v in module.other_security_group : k => v.id }
```

A literal ID (`vpc_id`, `prefix_list_id`, `referenced_security_group_id`) wins over its key.

### The three groups of a network appliance

A network appliance with a management, a private and a public interface, one group per interface. The `10.10.0.0/24` and `10.20.1.x` ranges are examples.

```hcl
security_groups = {
  app-mgmt = { # management: SSH and HTTPS from the management range only, the S3 prefix list out
    vpc_key = "Main"
    ingress_rules = {
      ssh   = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.10.0.0/24" }
      https = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.10.0.0/24" }
    }
    egress_rules = {
      s3 = { ip_protocol = "tcp", from_port = 443, to_port = 443, prefix_list_key = "s3" }
    }
  }
  app-private = { # private: GENEVE and the health check port from the GWLB (here its subnets' ranges, or a group with referenced_security_group_key)
    vpc_key = "Main"
    ingress_rules = {
      geneve-1a = { ip_protocol = "udp", from_port = 6081, to_port = 6081, cidr_ipv4 = "10.20.1.0/28" }
      health-1a = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.20.1.0/28" }
    }
    allow_all_egress = true
  }
  app-public = { # public: no inbound rule, egress all
    vpc_key          = "Main"
    allow_all_egress = true
  }
}
```

The provider removes the default allow-all egress rule of a new group, so a group that needs outbound traffic says so: `allow_all_egress = true` or an `egress_rules` entry.

A rule takes one source per entry (the provider's limit), so a source with several ranges, such as the subnets of several zones, is one entry per range; a blueprint builds the map with a `for` expression.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 6.68 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.71.0 |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [aws_security_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_vpc_security_group_egress_rule.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_rules_exclusive.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_rules_exclusive) | resource |
| [aws_vpc_security_group_vpc_association.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_vpc_association) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_env"></a> [env](#input\_env) | (Required) env value used in name generation | `string` | n/a | yes |
| <a name="input_prefix_list_ids"></a> [prefix\_list\_ids](#input\_prefix\_list\_ids) | Optional map of prefix list key to its ID. Resolves the prefix\_list\_key of the rules. e.g. { for k, v in module.vpc\_endpoint : k => v.prefix\_list\_id } | `map(string)` | `{}` | no |
| <a name="input_security_group"></a> [security\_group](#input\_security\_group) | (Required) Object describing the security group and its rules (see TFVars Parameters in the README). Optional `name` key overrides the auto-derived "<env>-<userDefinedString>-sg" name. | `any` | `{}` | no |
| <a name="input_security_group_ids"></a> [security\_group\_ids](#input\_security\_group\_ids) | Optional map of security group key to its ID. Resolves the referenced\_security\_group\_key of the rules. e.g. { for k, v in module.other\_security\_group : k => v.id }. Never the groups of the module block itself: a module that reads its own outputs waits for itself (a cycle). | `map(string)` | `{}` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags applied to all resources that take tags (merged with security\_group.tags) | `map(string)` | `{}` | no |
| <a name="input_userDefinedString"></a> [userDefinedString](#input\_userDefinedString) | (Required) UserDefinedString part of the name of the security group | `string` | n/a | yes |
| <a name="input_vpc_ids"></a> [vpc\_ids](#input\_vpc\_ids) | Optional map of VPC key to its ID. Resolves security\_group.vpc\_key and the vpc\_key of security\_group.vpc\_associations. e.g. { for k, v in module.vpc : k => v.id } | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_arn"></a> [arn](#output\_arn) | Returns the ARN of the security group |
| <a name="output_egress_rule_ids"></a> [egress\_rule\_ids](#output\_egress\_rule\_ids) | Returns the ID of each standalone egress rule, keyed as egress\_rules (allow-all-egress for allow\_all\_egress) |
| <a name="output_id"></a> [id](#output\_id) | Returns the ID of the security group (sg-...) |
| <a name="output_ingress_rule_ids"></a> [ingress\_rule\_ids](#output\_ingress\_rule\_ids) | Returns the ID of each standalone ingress rule, keyed as ingress\_rules |
| <a name="output_name"></a> [name](#output\_name) | Returns the name of the security group |
| <a name="output_object"></a> [object](#output\_object) | Returns the full aws\_security\_group resource object |
| <a name="output_owner_id"></a> [owner\_id](#output\_owner\_id) | Returns the ID of the account that owns the security group |
| <a name="output_vpc_id"></a> [vpc\_id](#output\_vpc\_id) | Returns the ID of the VPC of the security group |
<!-- END_TF_DOCS -->

## TFVars Parameters

Every key of the `security_group` object. A literal ID wins over its key.

| Parameter | Type | Default | Description |
| --------- | ---- | ------- | ----------- |
| `name` | string | `null` | Optional custom group name, used as the whole name (no suffix is added). When omitted, defaults to `"<env>-<userDefinedString>-sg"`. See [Naming](#naming). |
| `description` | string | `"Managed by Terraform"` | Description of the group, 1 to 255 characters (the plan fails otherwise). AWS allows letters, digits, spaces and `._-:/()#,@[]+=&;{}!$*`; the module does not check the characters. A change replaces the group. |
| `vpc_id` / `vpc_key` | string | n/a (one is required) | VPC of the group: a literal ID, or a key of the `vpc_ids` lookup map. A group with neither fails the plan, and so does a key that is not in the map. |
| `region` | string | provider region | Region of the group; also the default region of every resource of the module. |
| `revoke_rules_on_delete` | bool | `null` | Removes the rules of the group before it is deleted. |
| `timeouts` | object | `null` | `{ create, delete }` of the group. |
| `tags` | map(string) | `{}` | Merged with ESLZ-level tags; the Name tag always follows the naming standard. |
| `ingress_rules` | map(object) | `{}` | `aws_vpc_security_group_ingress_rule`, keyed by name. See the rule keys below. |
| `egress_rules` | map(object) | `{}` | `aws_vpc_security_group_egress_rule`, keyed by name. Same keys as an ingress rule. |
| `allow_all_egress` | bool | `false` | Adds the egress rule `allow-all-egress` (every protocol to `0.0.0.0/0`), beside `egress_rules`. An `egress_rules` entry with that key fails the plan, since it would replace the generated rule. |
| `rules_exclusive` | object | `null` | Set it (even to `{}`) to create `aws_vpc_security_group_rules_exclusive` over the rules above: the provider then removes every other rule found on the group. `{ region }`. Not with inline rules. |
| `vpc_associations` | map(object) | `{}` | `aws_vpc_security_group_vpc_association`, keyed by name: `{ vpc_id or vpc_key, region, timeouts = { create, delete } }`. The key resolves through the `vpc_ids` lookup map; a key that is not in the map, or an attribute outside these four, fails the plan. |
| `inline_ingress_rules` / `inline_egress_rules` | list(object) | `null` | The legacy inline `ingress` and `egress` of `aws_security_group`: `{ protocol (required), from_port, to_port, cidr_blocks, ipv6_cidr_blocks, prefix_list_ids, security_groups, self, description }`, a missing field taking the zero value the provider wants. `null` leaves the rules to the provider; `[]` removes every rule, the default egress one included. The provider cannot manage the same group's rules inline and as standalone resources, so the plan fails when either is set beside `ingress_rules`, `egress_rules`, `allow_all_egress` or `rules_exclusive`. Prefer the standalone rules. |

Keys of a rule (`ingress_rules`, `egress_rules`). Exactly one source per rule: `cidr_ipv4`, `cidr_ipv6`, a prefix list, a security group, or `self`. A rule is checked before it is planned, and the plan fails naming the rule and every problem found: an attribute outside the table below (a typo such as `cidr_ipv_4` is refused, not ignored), no source or two, a `prefix_list_key` or `referenced_security_group_key` that is not in its lookup map, a missing or unknown `ip_protocol`, and ports that do not fit the protocol (the provider's rules: `from_port` and `to_port` are required unless the protocol is `-1` or `icmpv6`, and not set with `-1`). Another protocol number takes no check on its ports. The same refusal of an unknown attribute applies to the object itself, an inline rule, `rules_exclusive` and an association.

| Parameter | Type | Default | Description |
| --------- | ---- | ------- | ----------- |
| `ip_protocol` | string | n/a (required) | `tcp`, `udp`, `icmp`, `icmpv6`, a protocol number from 0 to 255 (a number is passed as a string), or `-1` for every protocol (then no port). |
| `from_port` / `to_port` | number | `null` | `tcp` and `udp`: the port range, 0 to 65535, `from_port` not above `to_port`, both required. `icmp`: the type and the code, -1 to 255 (`-1` for all), both required. `icmpv6`: the same, both or neither. `-1`: neither. |
| `cidr_ipv4` / `cidr_ipv6` | string | `null` | Source (ingress) or destination (egress) range. |
| `prefix_list_id` / `prefix_list_key` | string | `null` | A managed prefix list: a literal ID, or a key of the `prefix_list_ids` lookup map (for the S3 prefix list, the `prefix_list_id` output of the S3 gateway endpoint). |
| `referenced_security_group_id` / `referenced_security_group_key` | string | `null` | Another group: a literal ID, or a key of the `security_group_ids` lookup map. |
| `self` | bool | `false` | The group itself (members of the group). |
| `description` | string | `null` | Description of the rule. |
| `region` | string | the `region` of the object | Region of the rule. |
| `tags` | map(string) | `{}` | Merged with ESLZ-level tags and the module tag; the Name tag is `<group Name tag>-in-<key>` or `-out-<key>`. |

## Scope

`scripts/coverage_check.sh hashicorp/aws 6.71.0 aws_vpc_security_group .` (the skill's parity check, run on this module) lists four resources, all covered:

- `aws_vpc_security_group_ingress_rule`
- `aws_vpc_security_group_egress_rule`
- `aws_vpc_security_group_rules_exclusive`
- `aws_vpc_security_group_vpc_association`

`scripts/coverage_check.sh hashicorp/aws 6.71.0 aws_security_group .` lists two, and the module covers `aws_security_group` (the group, with its legacy inline rules). The other one is deliberately **out of scope**, so the script reports it as "missing" and only it:

- `aws_security_group_rule`: the legacy standalone rule. The provider documentation tells to avoid it for `aws_vpc_security_group_ingress_rule` and `_egress_rule` (it struggles with several CIDR blocks and, historically, has no unique ID, tags or descriptions of its own). The module has the current resources, so a caller of the old one moves its rules to `ingress_rules` and `egress_rules`.

`aws_default_security_group` does not share the prefix: it adopts the default group of a VPC and manages its rules, which belongs with the VPC module, not with a module that creates groups.

## Naming

Names follow [`AWS-Naming-and-Tagging-Suffixes.md`](../../../Documentation/Standards/AWS-Naming-and-Tagging-Suffixes.md): `<env>-<userDefinedString>-sg` (`sg` is the suffix the document lists for a security group), letters, digits and hyphens, with the case kept. The limits come from the AWS rules for a group name and a tag value, and the committed test runs pin the boundaries: the 252-character cut of the base (a hyphen before it, on it and after it), `sg` and `SG-` at the start of the base, an `env` that sanitizes to nothing, a leading hyphen in the key, the custom-name cut at 255 after the `sg-` change, the Name tag characters and the 256-character cut of a rule's Name tag:

- **Group name** (`aws_security_group.name`): at most 255 characters; letters, digits and `._-:/()#,@[]+=&;{}!$*` (AWS allows a space as well; the module leaves it out); it may not start with `sg-`. The derived base is cut at 252 so that `-sg` fits, and trimmed of a hyphen the cut or an empty `env` leaves at either end; a base that is empty leaves `sg`. A base of `sg` alone or before a hyphen (`sg`, `SG-web`) becomes `sg0` (`sg0-sg`, `SG0-web-sg`) so that the name never starts with `sg-`. The module treats the reserved prefix as case-insensitive, which AWS does not document, to be safe. A custom `name` keeps the case and every character AWS allows, drops the others, has `sg-` changed to `sg0-` and is then cut at 255 (in that order, since the change adds a character); a custom name with no allowed character falls back to the derived one.
- **Name tag** (the group and every rule): the group name without the characters a tag value does not allow (it takes letters, digits, spaces and `_.:/=+-@`), so a custom name with a parenthesis or a `#` still gives a valid tag. The Name tag of a rule is `<group Name tag>-in-<key>` or `-out-<key>`, the key cleaned the same way, and cut at 256 characters.
- The exclusive rule set and the VPC associations have no name and no tags, so nothing is derived for them.

## Ingress and the standard

The module accepts the rules the caller sets. It does not check them against [`Network-Security-Ingress-Authoritative-Segmentation.md`](../../../Documentation/Standards/Network-Security-Ingress-Authoritative-Segmentation.md), under which a destination SHALL NOT admit inbound traffic from every address except a service deliberately exposed to the public: that guard (`/0` ranges in ingress rules) is the caller's, as in the blueprints that call `terraform-aws-caf-linux_virtual_machine`.

## Known limits

- **A module instance cannot read the groups of its own `for_each`.** `security_group_ids = { for k, v in module.security_group : k => v.id }` inside the call of `module.security_group` makes a cycle in OpenTofu (the rules wait for the module to close, and the module closes after the rules). `referenced_security_group_key` resolves groups made by another module block (`module.other_security_group`, one way), and `self = true` references the group itself. Two groups that reference each other need their rules in separate resources, which this module does not take.
- A change of `name` or `description` replaces the group (the provider forces a new group), and so every group that references it.
