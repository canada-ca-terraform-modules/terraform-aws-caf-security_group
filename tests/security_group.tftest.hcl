# One run per feature, proving both presence (when configured) and absence (when not), the rejections each beside an accepting
# run of the same fixture, and the naming edge cases the runs below pin: the 252-character cut of the base (a hyphen on the cut,
# before it and after it), "sg" at the start of the base, an env that sanitizes to nothing, a leading hyphen, the custom-name cut at
# 255 after the sg- change and the 256-character cut of a rule's Name tag. The base object is the management group of a network
# appliance; the private and public groups have their own runs.

mock_provider "aws" {}

variables {
  env               = "Dev"
  userDefinedString = "app-mgmt"
  tags              = { environment = "test" }
  vpc_ids = {
    Main   = "vpc-00000000000000001"
    Spoke  = "vpc-00000000000000002"
    Shared = "vpc-00000000000000003"
  }
  prefix_list_ids = {
    s3 = "pl-00000000000000001"
  }
  security_group_ids = {
    app-private = "sg-00000000000000001"
    app-public  = "sg-00000000000000002"
  }
  security_group = {
    vpc_key = "Main"
  }
}

# ---------------------------------------------------------------------------
# the group
# ---------------------------------------------------------------------------
run "group_defaults" {
  command = plan

  assert {
    condition     = aws_security_group.this.name == "Dev-app-mgmt-sg"
    error_message = "The derived name must be <env>-<userDefinedString>-sg with the case kept"
  }
  assert {
    condition     = aws_security_group.this.vpc_id == "vpc-00000000000000001"
    error_message = "vpc_key must resolve through the vpc_ids lookup map"
  }
  assert {
    condition     = aws_security_group.this.description == "Managed by Terraform"
    error_message = "The description must default to the provider's own default"
  }
  assert {
    condition     = aws_security_group.this.tags["environment"] == "test" && aws_security_group.this.tags["module"] == "terraform-aws-caf-security_group"
    error_message = "ESLZ tags and the module tag must be applied"
  }
  assert {
    condition     = aws_security_group.this.tags["Name"] == "Dev-app-mgmt-sg"
    error_message = "The Name tag must equal the group name"
  }
}

run "literal_vpc_id_wins_over_vpc_key" {
  command = plan

  variables {
    security_group = {
      vpc_id  = "vpc-0000000000000ffff"
      vpc_key = "Main"
    }
  }

  assert {
    condition     = aws_security_group.this.vpc_id == "vpc-0000000000000ffff"
    error_message = "A literal vpc_id must win over vpc_key"
  }
}

run "unknown_vpc_key_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Missing"
    }
  }

  expect_failures = [aws_security_group.this]
}

run "optional_arguments_are_passed_through" {
  command = plan

  variables {
    security_group = {
      vpc_key                = "Main"
      description            = "Management interface of the appliance"
      revoke_rules_on_delete = true
      region                 = "ca-central-1"
      timeouts               = { create = "5m", delete = "10m" }
      tags                   = { owner = "team-x" }
    }
  }

  assert {
    condition     = aws_security_group.this.description == "Management interface of the appliance"
    error_message = "description must be passed through"
  }
  assert {
    condition     = aws_security_group.this.revoke_rules_on_delete == true
    error_message = "revoke_rules_on_delete must be passed through"
  }
  assert {
    condition     = aws_security_group.this.region == "ca-central-1"
    error_message = "region must be passed through"
  }
  assert {
    condition     = aws_security_group.this.tags["owner"] == "team-x" && aws_security_group.this.tags["environment"] == "test"
    error_message = "The tags of the object must be merged with the ESLZ tags"
  }
}

run "name_tag_wins_over_a_tag_of_the_object" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      tags    = { Name = "something-else" }
    }
  }

  assert {
    condition     = aws_security_group.this.tags["Name"] == "Dev-app-mgmt-sg"
    error_message = "The Name tag must follow the naming standard, not the object's tags"
  }
}

# ---------------------------------------------------------------------------
# no rule by default
# ---------------------------------------------------------------------------
run "rules_are_absent_by_default" {
  command = plan

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.this) == 0
    error_message = "No ingress rule must be created by default"
  }
  assert {
    condition     = length(aws_vpc_security_group_egress_rule.this) == 0
    error_message = "No egress rule must be created by default (the provider drops the default allow-all rule too)"
  }
  assert {
    condition     = length(aws_vpc_security_group_rules_exclusive.this) == 0
    error_message = "The exclusive rule set must not be created by default"
  }
  assert {
    condition     = length(aws_vpc_security_group_vpc_association.this) == 0
    error_message = "No VPC association must be created by default"
  }
}

# ---------------------------------------------------------------------------
# management group: SSH and HTTPS from one CIDR, egress to the S3 prefix list
# ---------------------------------------------------------------------------
run "management_group_rules" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      ingress_rules = {
        ssh   = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.10.0.0/24", description = "SSH from the Security MRZ" }
        https = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.10.0.0/24", description = "HTTPS from the Security MRZ" }
      }
      egress_rules = {
        s3 = { ip_protocol = "tcp", from_port = 443, to_port = 443, prefix_list_key = "s3", description = "Configuration bucket through the S3 prefix list" }
      }
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.this) == 2
    error_message = "One ingress rule per entry"
  }
  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.this["ssh"].ip_protocol == "tcp" &&
      aws_vpc_security_group_ingress_rule.this["ssh"].from_port == 22 &&
      aws_vpc_security_group_ingress_rule.this["ssh"].to_port == 22 &&
      aws_vpc_security_group_ingress_rule.this["ssh"].cidr_ipv4 == "10.10.0.0/24" &&
      aws_vpc_security_group_ingress_rule.this["ssh"].description == "SSH from the Security MRZ"
    )
    error_message = "The SSH rule must carry its protocol, port, source and description"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["https"].from_port == 443 && aws_vpc_security_group_ingress_rule.this["https"].cidr_ipv4 == "10.10.0.0/24"
    error_message = "The HTTPS rule must carry its port and source"
  }
  assert {
    condition     = length(aws_vpc_security_group_egress_rule.this) == 1
    error_message = "One egress rule per entry"
  }
  assert {
    condition     = aws_vpc_security_group_egress_rule.this["s3"].prefix_list_id == "pl-00000000000000001" && aws_vpc_security_group_egress_rule.this["s3"].cidr_ipv4 == null
    error_message = "prefix_list_key must resolve through the prefix_list_ids lookup map"
  }
}

# ---------------------------------------------------------------------------
# private group: GENEVE and the health check, from CIDRs or another group
# ---------------------------------------------------------------------------
run "private_group_rules_from_cidrs_and_a_group" {
  command = plan

  variables {
    userDefinedString = "app-private"
    security_group = {
      vpc_key = "Main"
      ingress_rules = {
        geneve-a = { ip_protocol = "udp", from_port = 6081, to_port = 6081, cidr_ipv4 = "10.20.1.0/28" }
        geneve-b = { ip_protocol = "udp", from_port = 6081, to_port = 6081, cidr_ipv4 = "10.20.1.16/28" }
        health   = { ip_protocol = "tcp", from_port = 443, to_port = 443, referenced_security_group_key = "app-public" }
        v6       = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv6 = "2001:db8::/64" }
      }
    }
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["geneve-a"].ip_protocol == "udp" && aws_vpc_security_group_ingress_rule.this["geneve-a"].from_port == 6081 && aws_vpc_security_group_ingress_rule.this["geneve-b"].cidr_ipv4 == "10.20.1.16/28"
    error_message = "GENEVE rules must carry their protocol, port and CIDR"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["health"].referenced_security_group_id == "sg-00000000000000002" && aws_vpc_security_group_ingress_rule.this["health"].cidr_ipv4 == null
    error_message = "referenced_security_group_key must resolve through the security_group_ids lookup map"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["v6"].cidr_ipv6 == "2001:db8::/64"
    error_message = "cidr_ipv6 must be passed through"
  }
}

run "literal_ids_win_over_keys" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      ingress_rules = {
        group = { ip_protocol = "tcp", from_port = 443, to_port = 443, referenced_security_group_id = "sg-0000000000000ffff", referenced_security_group_key = "app-public" }
      }
      egress_rules = {
        list = { ip_protocol = "-1", prefix_list_id = "pl-0000000000000ffff", prefix_list_key = "s3" }
      }
    }
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["group"].referenced_security_group_id == "sg-0000000000000ffff"
    error_message = "A literal referenced_security_group_id must win over its key"
  }
  assert {
    condition     = aws_vpc_security_group_egress_rule.this["list"].prefix_list_id == "pl-0000000000000ffff"
    error_message = "A literal prefix_list_id must win over its key"
  }
}

run "a_rule_can_reference_its_own_group" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      ingress_rules = {
        cluster = { ip_protocol = "-1", self = true, description = "Members of the group" }
      }
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.this) == 1
    error_message = "A rule with self = true is one rule"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["cluster"].ip_protocol == "-1" && aws_vpc_security_group_ingress_rule.this["cluster"].from_port == null
    error_message = "An all-protocol rule must set no port"
  }
}

# ---------------------------------------------------------------------------
# public group: no inbound, egress all
# ---------------------------------------------------------------------------
run "public_group_allows_all_egress_and_no_inbound" {
  command = plan

  variables {
    userDefinedString = "app-public"
    security_group = {
      vpc_key          = "Main"
      allow_all_egress = true
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.this) == 0
    error_message = "The public group has no inbound rule"
  }
  assert {
    condition     = length(aws_vpc_security_group_egress_rule.this) == 1 && aws_vpc_security_group_egress_rule.this["allow-all-egress"].ip_protocol == "-1" && aws_vpc_security_group_egress_rule.this["allow-all-egress"].cidr_ipv4 == "0.0.0.0/0"
    error_message = "allow_all_egress must create one rule for every protocol to 0.0.0.0/0"
  }
}

run "allow_all_egress_is_off_by_default" {
  command = plan

  variables {
    security_group = {
      vpc_key          = "Main"
      allow_all_egress = false
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_egress_rule.this) == 0
    error_message = "allow_all_egress = false must create no egress rule"
  }
}

# ---------------------------------------------------------------------------
# rule attributes: region, tags, the Name tag of a rule
# ---------------------------------------------------------------------------
run "rule_tags_region_and_name_tag" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      region  = "ca-central-1"
      ingress_rules = {
        ssh = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.10.0.0/24", tags = { purpose = "admin" } }
      }
      egress_rules = {
        web = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8", region = "ca-west-1" }
      }
    }
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["ssh"].tags["Name"] == "Dev-app-mgmt-sg-in-ssh" && aws_vpc_security_group_ingress_rule.this["ssh"].tags["purpose"] == "admin" && aws_vpc_security_group_ingress_rule.this["ssh"].tags["environment"] == "test"
    error_message = "A rule carries the ESLZ tags, its own tags and a Name tag of <group name>-in-<key>"
  }
  assert {
    condition     = aws_vpc_security_group_egress_rule.this["web"].tags["Name"] == "Dev-app-mgmt-sg-out-web" && aws_vpc_security_group_egress_rule.this["web"].tags["module"] == "terraform-aws-caf-security_group"
    error_message = "An egress rule carries a Name tag of <group name>-out-<key> and the module tag"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["ssh"].region == "ca-central-1" && aws_vpc_security_group_egress_rule.this["web"].region == "ca-west-1"
    error_message = "A rule takes the region of the object unless it sets its own"
  }
}

# ---------------------------------------------------------------------------
# a rule names exactly one source, and a key must resolve
# (each fixture breaks only the rule it names)
# ---------------------------------------------------------------------------
run "a_rule_with_no_source_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { none = { ip_protocol = "tcp", from_port = 22, to_port = 22 } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "a_rule_with_two_sources_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key      = "Main"
      egress_rules = { two = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8", prefix_list_key = "s3" } }
    }
  }

  expect_failures = [aws_vpc_security_group_egress_rule.this]
}

run "a_rule_with_a_cidr_and_self_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { two = { ip_protocol = "-1", cidr_ipv4 = "10.0.0.0/8", self = true } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "an_unknown_security_group_key_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { bad = { ip_protocol = "tcp", from_port = 443, to_port = 443, referenced_security_group_key = "Missing" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "an_unknown_prefix_list_key_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key      = "Main"
      egress_rules = { bad = { ip_protocol = "tcp", from_port = 443, to_port = 443, prefix_list_key = "Missing" } }
    }
  }

  expect_failures = [aws_vpc_security_group_egress_rule.this]
}

# ---------------------------------------------------------------------------
# inline rules (legacy): passed through, and never mixed with standalone rules
# ---------------------------------------------------------------------------
run "inline_rules_are_passed_through" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      inline_ingress_rules = [
        { protocol = "tcp", from_port = 22, to_port = 22, cidr_blocks = ["10.10.0.0/24"], description = "SSH" },
        { protocol = "-1", self = true },
      ]
      inline_egress_rules = [
        { protocol = "-1", cidr_blocks = ["0.0.0.0/0"] },
      ]
    }
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 2 && length(aws_security_group.this.egress) == 1
    error_message = "Inline rules must be passed to the group"
  }
  assert {
    condition     = length([for r in aws_security_group.this.ingress : r if r.from_port == 22 && r.protocol == "tcp" && contains(r.cidr_blocks, "10.10.0.0/24") && r.description == "SSH"]) == 1
    error_message = "An inline rule must carry its protocol, port, CIDRs and description"
  }
  assert {
    condition     = length([for r in aws_security_group.this.ingress : r if r.self == true && r.protocol == "-1"]) == 1
    error_message = "An inline rule must default its missing fields (self here) and keep the ones it sets"
  }
}

run "an_empty_inline_list_removes_every_rule" {
  command = plan

  variables {
    security_group = {
      vpc_key             = "Main"
      inline_egress_rules = []
    }
  }

  assert {
    condition     = length(aws_security_group.this.egress) == 0
    error_message = "An empty inline_egress_rules must be passed as an empty set (it removes the default allow-all rule), not left unset"
  }
}

run "inline_rules_with_standalone_rules_fail" {
  command = plan

  variables {
    security_group = {
      vpc_key              = "Main"
      inline_ingress_rules = [{ protocol = "tcp", from_port = 22, to_port = 22, cidr_blocks = ["10.10.0.0/24"] }]
      ingress_rules        = { ssh = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.10.0.0/24" } }
    }
  }

  expect_failures = [aws_security_group.this]
}

# ---------------------------------------------------------------------------
# exclusive rule set and extra VPC associations
# ---------------------------------------------------------------------------
run "rules_exclusive_is_created_when_configured" {
  command = plan

  variables {
    security_group = {
      vpc_key         = "Main"
      rules_exclusive = {}
      ingress_rules = {
        ssh = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.10.0.0/24" }
      }
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_rules_exclusive.this) == 1
    error_message = "rules_exclusive = {} must create the exclusive rule set"
  }
}

run "rules_exclusive_takes_a_region" {
  command = plan

  variables {
    security_group = {
      vpc_key         = "Main"
      rules_exclusive = { region = "ca-central-1" }
    }
  }

  assert {
    condition     = aws_vpc_security_group_rules_exclusive.this["enabled"].region == "ca-central-1"
    error_message = "The region of rules_exclusive must be passed through"
  }
}

run "vpc_associations_are_created_per_entry" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      vpc_associations = {
        spoke  = { vpc_key = "Spoke" }
        shared = { vpc_id = "vpc-0000000000000ffff", region = "ca-central-1", timeouts = { create = "5m", delete = "5m" } }
      }
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_vpc_association.this) == 2
    error_message = "One association per entry"
  }
  assert {
    condition     = aws_vpc_security_group_vpc_association.this["spoke"].vpc_id == "vpc-00000000000000002"
    error_message = "vpc_key must resolve through the vpc_ids lookup map"
  }
  assert {
    condition     = aws_vpc_security_group_vpc_association.this["shared"].vpc_id == "vpc-0000000000000ffff" && aws_vpc_security_group_vpc_association.this["shared"].region == "ca-central-1"
    error_message = "A literal vpc_id and the region must be passed through"
  }
}

run "an_association_with_an_unknown_vpc_key_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key          = "Main"
      vpc_associations = { bad = { vpc_key = "Missing" } }
    }
  }

  expect_failures = [aws_vpc_security_group_vpc_association.this]
}

# ---------------------------------------------------------------------------
# the protocol and the ports of a rule: each rejection names one rule and one
# problem, and sits beside the accepting run of the same shape
# ---------------------------------------------------------------------------
run "rule_protocols_and_ports_are_accepted" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      ingress_rules = {
        tcp-low   = { ip_protocol = "tcp", from_port = 0, to_port = 65535, cidr_ipv4 = "10.0.0.0/8" }
        udp       = { ip_protocol = "udp", from_port = 6081, to_port = 6081, cidr_ipv4 = "10.0.0.0/8" }
        icmp-all  = { ip_protocol = "icmp", from_port = -1, to_port = -1, cidr_ipv4 = "10.0.0.0/8" }
        icmp-echo = { ip_protocol = "icmp", from_port = 8, to_port = 0, cidr_ipv4 = "10.0.0.0/8" }
        icmpv6    = { ip_protocol = "icmpv6", cidr_ipv6 = "2001:db8::/64" }
        icmpv6-nd = { ip_protocol = "icmpv6", from_port = 135, to_port = 0, cidr_ipv6 = "2001:db8::/64" }
        all       = { ip_protocol = "-1", cidr_ipv4 = "10.0.0.0/8" }
        gre       = { ip_protocol = "47", cidr_ipv4 = "10.0.0.0/8" }
        numeric   = { ip_protocol = 6, from_port = "443", to_port = 443, cidr_ipv4 = "10.0.0.0/8" }
        all-num   = { ip_protocol = -1, cidr_ipv4 = "10.0.0.0/8" }
      }
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.this) == 10
    error_message = "Every sound protocol and port shape must be accepted"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["numeric"].ip_protocol == "6" && aws_vpc_security_group_ingress_rule.this["all-num"].ip_protocol == "-1"
    error_message = "A protocol given as a number is passed to the provider as a string"
  }
}

run "an_unknown_protocol_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { web = { ip_protocol = "http", from_port = 80, to_port = 80, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "a_protocol_number_above_255_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key      = "Main"
      egress_rules = { gre = { ip_protocol = "256", cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_egress_rule.this]
}

run "a_missing_protocol_fails_with_a_message_naming_the_rule" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { no-protocol = { from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "ports_with_every_protocol_fail" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { all = { ip_protocol = "-1", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "tcp_without_ports_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { ssh = { ip_protocol = "tcp", cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "udp_with_one_port_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key      = "Main"
      egress_rules = { dns = { ip_protocol = "udp", from_port = 53, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_egress_rule.this]
}

run "icmp_without_type_and_code_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { ping = { ip_protocol = "icmp", cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "icmpv6_with_only_a_type_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { nd = { ip_protocol = "icmpv6", from_port = 135, cidr_ipv6 = "2001:db8::/64" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "a_port_range_that_runs_backwards_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { backwards = { ip_protocol = "tcp", from_port = 443, to_port = 22, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "a_port_above_65535_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { high = { ip_protocol = "tcp", from_port = 22, to_port = 65536, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "a_negative_tcp_port_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key      = "Main"
      egress_rules = { all = { ip_protocol = "tcp", from_port = -1, to_port = 443, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_egress_rule.this]
}

run "an_icmp_type_above_255_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { ping = { ip_protocol = "icmp", from_port = 256, to_port = 0, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "a_port_that_is_not_a_number_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { web = { ip_protocol = "tcp", from_port = "http", to_port = 80, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

# ---------------------------------------------------------------------------
# a key nobody reads is a typo: a rule, the object, an inline rule, the
# exclusive set and an association refuse one
# ---------------------------------------------------------------------------
run "an_unknown_rule_key_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key       = "Main"
      ingress_rules = { ssh = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.10.0.0/24", desciption = "typo" } }
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this]
}

run "an_unknown_egress_rule_key_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key      = "Main"
      egress_rules = { web = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv_4 = "10.0.0.0/8", prefix_list_key = "s3" } }
    }
  }

  expect_failures = [aws_vpc_security_group_egress_rule.this]
}

run "an_unknown_key_of_the_object_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key      = "Main"
      ingres_rules = {}
    }
  }

  expect_failures = [aws_security_group.this]
}

run "an_unknown_key_of_an_inline_rule_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key              = "Main"
      inline_ingress_rules = [{ protocol = "tcp", from_port = 22, to_port = 22, cidr_blocks = ["10.10.0.0/24"], cidr_block = ["10.0.0.0/8"] }]
    }
  }

  expect_failures = [aws_security_group.this]
}

run "an_unknown_key_of_rules_exclusive_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key         = "Main"
      rules_exclusive = { regions = "ca-central-1" }
    }
  }

  expect_failures = [aws_security_group.this]
}

run "an_unknown_key_of_an_association_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key          = "Main"
      vpc_associations = { spoke = { vpc_key = "Spoke", vpc_keys = ["Shared"] } }
    }
  }

  expect_failures = [aws_vpc_security_group_vpc_association.this]
}

# ---------------------------------------------------------------------------
# allow_all_egress and an entry of the same key
# ---------------------------------------------------------------------------
run "allow_all_egress_beside_other_egress_rules_is_accepted" {
  command = plan

  variables {
    security_group = {
      vpc_key          = "Main"
      allow_all_egress = true
      egress_rules     = { s3 = { ip_protocol = "tcp", from_port = 443, to_port = 443, prefix_list_key = "s3" } }
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_egress_rule.this) == 2 && aws_vpc_security_group_egress_rule.this["allow-all-egress"].cidr_ipv4 == "0.0.0.0/0"
    error_message = "The generated rule and the caller's rules must both exist"
  }
}

run "an_entry_named_allow_all_egress_with_allow_all_egress_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key          = "Main"
      allow_all_egress = true
      egress_rules     = { allow-all-egress = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_security_group.this]
}

run "an_entry_named_allow_all_egress_without_allow_all_egress_is_accepted" {
  command = plan

  variables {
    security_group = {
      vpc_key      = "Main"
      egress_rules = { allow-all-egress = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.this["allow-all-egress"].from_port == 443
    error_message = "Without allow_all_egress the key is the caller's"
  }
}

# ---------------------------------------------------------------------------
# the description: 1 to 255 characters
# ---------------------------------------------------------------------------
run "description_of_one_and_of_255_characters_is_accepted" {
  command = plan

  variables {
    security_group = {
      vpc_key     = "Main"
      description = join("", [for i in range(255) : "d"])
    }
  }

  assert {
    condition     = length(aws_security_group.this.description) == 255
    error_message = "A description of 255 characters is the longest AWS takes"
  }
}

run "an_empty_description_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key     = "Main"
      description = ""
    }
  }

  expect_failures = [aws_security_group.this]
}

run "a_description_of_256_characters_fails" {
  command = plan

  variables {
    security_group = {
      vpc_key     = "Main"
      description = join("", [for i in range(256) : "d"])
    }
  }

  expect_failures = [aws_security_group.this]
}

# ---------------------------------------------------------------------------
# the VPC is required
# ---------------------------------------------------------------------------
run "a_group_with_no_vpc_fails" {
  command = plan

  variables {
    security_group = {
      description = "No VPC given"
    }
  }

  expect_failures = [aws_security_group.this]
}

# ---------------------------------------------------------------------------
# inline rules refuse every standalone way of managing rules, each beside
# the accepting run of the same fixture without the inline rules
# ---------------------------------------------------------------------------
run "inline_ingress_rules_alone_are_accepted" {
  command = plan

  variables {
    security_group = {
      vpc_key              = "Main"
      inline_ingress_rules = [{ protocol = "tcp", from_port = 22, to_port = 22, cidr_blocks = ["10.10.0.0/24"] }]
    }
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 1 && length(aws_vpc_security_group_ingress_rule.this) == 0
    error_message = "Inline rules alone must be accepted"
  }
}

run "inline_rules_with_egress_rules_fail" {
  command = plan

  variables {
    security_group = {
      vpc_key              = "Main"
      inline_ingress_rules = [{ protocol = "tcp", from_port = 22, to_port = 22, cidr_blocks = ["10.10.0.0/24"] }]
      egress_rules         = { web = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  expect_failures = [aws_security_group.this]
}

run "egress_rules_alone_are_accepted" {
  command = plan

  variables {
    security_group = {
      vpc_key      = "Main"
      egress_rules = { web = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8" } }
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_egress_rule.this) == 1
    error_message = "Standalone egress rules alone must be accepted"
  }
}

run "inline_rules_with_allow_all_egress_fail" {
  command = plan

  variables {
    security_group = {
      vpc_key             = "Main"
      inline_egress_rules = []
      allow_all_egress    = true
    }
  }

  expect_failures = [aws_security_group.this]
}

run "allow_all_egress_alone_is_accepted" {
  command = plan

  variables {
    security_group = {
      vpc_key          = "Main"
      allow_all_egress = true
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_egress_rule.this) == 1
    error_message = "allow_all_egress alone must be accepted"
  }
}

run "inline_rules_with_rules_exclusive_fail" {
  command = plan

  variables {
    security_group = {
      vpc_key              = "Main"
      inline_ingress_rules = [{ protocol = "tcp", from_port = 22, to_port = 22, cidr_blocks = ["10.10.0.0/24"] }]
      rules_exclusive      = {}
    }
  }

  expect_failures = [aws_security_group.this]
}

run "rules_exclusive_alone_is_accepted" {
  command = plan

  variables {
    security_group = {
      vpc_key         = "Main"
      rules_exclusive = {}
    }
  }

  assert {
    condition     = length(aws_vpc_security_group_rules_exclusive.this) == 1
    error_message = "rules_exclusive alone must be accepted"
  }
}

# ---------------------------------------------------------------------------
# naming: limits of aws_security_group.name (at most 255 characters,
# [0-9A-Za-z._-:/()#,@[]+=&;{}!$*], not starting with "sg-"); the Name tag
# takes letters, digits, spaces and _ . : / = + - @ up to 256 characters
# ---------------------------------------------------------------------------
run "naming_minimum_length_when_env_and_key_sanitize_to_nothing" {
  command = plan

  variables {
    env               = "!!"
    userDefinedString = "??"
  }

  assert {
    condition     = aws_security_group.this.name == "sg"
    error_message = "An empty base must leave only the suffix, with no hyphen at the start"
  }
}

run "naming_special_characters_are_stripped_from_the_derived_name" {
  command = plan

  variables {
    env               = "G3 Pg"
    userDefinedString = "App_mgmt.1"
  }

  assert {
    condition     = aws_security_group.this.name == "G3Pg-Appmgmt1-sg"
    error_message = "The derived name keeps letters, digits and hyphens, and the case"
  }
}

run "naming_maximum_length_cuts_the_base_so_the_suffix_fits" {
  command = plan

  variables {
    userDefinedString = join("", [for i in range(300) : "a"])
  }

  assert {
    condition     = length(aws_security_group.this.name) == 255 && endswith(aws_security_group.this.name, "-sg")
    error_message = "A derived name must be exactly 255 characters at most and keep its -sg suffix"
  }
  assert {
    condition     = length(aws_security_group.this.tags["Name"]) == 255
    error_message = "The Name tag must equal the group name"
  }
}

# The cut falls on a hyphen: "Dev-" is 4 characters and 247 a's make 251, so the 252nd character of the base is the hyphen.
run "naming_truncation_boundary_does_not_leave_a_hyphen_before_the_suffix" {
  command = plan

  variables {
    userDefinedString = "${join("", [for i in range(247) : "a"])}-bbbb"
  }

  assert {
    condition     = aws_security_group.this.name == "Dev-${join("", [for i in range(247) : "a"])}-sg"
    error_message = "The hyphen the cut lands on must be trimmed, not doubled before the suffix"
  }
  assert {
    condition     = !strcontains(aws_security_group.this.name, "--")
    error_message = "No doubled hyphen"
  }
}

run "naming_sg_prefix_of_the_base_is_changed" {
  command = plan

  variables {
    env               = ""
    userDefinedString = "sg"
  }

  assert {
    condition     = aws_security_group.this.name == "sg0-sg"
    error_message = "A name must not start with sg-: a base of sg becomes sg0"
  }
}

run "naming_sg_prefix_is_case_insensitive" {
  command = plan

  variables {
    env               = ""
    userDefinedString = "SG-web"
  }

  assert {
    condition     = aws_security_group.this.name == "SG0-web-sg"
    error_message = "A base starting with SG- must be changed whatever its case"
  }
}

run "naming_custom_name_override" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      name    = "My App/mgmt (R&D)_1!"
    }
  }

  assert {
    condition     = aws_security_group.this.name == "MyApp/mgmt(R&D)_1!"
    error_message = "A custom name replaces the derived one, keeps its case and the characters AWS allows, and drops the others (the space here)"
  }
  assert {
    condition     = aws_security_group.this.tags["Name"] == "MyApp/mgmtRD_1"
    error_message = "The Name tag is the group name without the characters a tag does not allow"
  }
}

run "naming_custom_name_of_only_disallowed_characters_falls_back_to_the_derived_name" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      name    = "   "
    }
  }

  assert {
    condition     = aws_security_group.this.name == "Dev-app-mgmt-sg"
    error_message = "A custom name with no allowed character must fall back to the derived name"
  }
}

run "naming_custom_name_starting_with_sg_is_changed" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      name    = "sg-appliance"
    }
  }

  assert {
    condition     = aws_security_group.this.name == "sg0-appliance"
    error_message = "A custom name must not start with sg-"
  }
}

run "naming_custom_name_is_cut_at_255_after_the_sg_prefix_change" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      name    = "sg-${join("", [for i in range(300) : "b"])}"
    }
  }

  assert {
    condition     = length(aws_security_group.this.name) == 255 && startswith(aws_security_group.this.name, "sg0-")
    error_message = "The sg- change adds a character, so the cut to 255 must come after it"
  }
}

run "naming_name_tag_drops_characters_a_tag_does_not_allow" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      name    = "app(1)#a,b[c]&d;e{f}!g$h*i@j"
    }
  }

  assert {
    condition     = aws_security_group.this.name == "app(1)#a,b[c]&d;e{f}!g$h*i@j"
    error_message = "The group name keeps every character AWS allows in a group name"
  }
  assert {
    condition     = aws_security_group.this.tags["Name"] == "app1abcdefghi@j"
    error_message = "The Name tag keeps only letters, digits and _ . : / = + - @"
  }
}

run "naming_rule_name_tag_is_cut_at_256" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      name    = join("", [for i in range(255) : "c"])
      ingress_rules = {
        (join("", [for i in range(300) : "k"])) = { ip_protocol = "-1", self = true }
      }
    }
  }

  assert {
    condition     = alltrue([for r in aws_vpc_security_group_ingress_rule.this : length(r.tags["Name"]) == 256])
    error_message = "The Name tag of a rule must be cut to 256 characters"
  }
}

run "naming_rule_key_characters_a_tag_does_not_allow_are_dropped_from_the_name_tag" {
  command = plan

  variables {
    security_group = {
      vpc_key = "Main"
      ingress_rules = {
        "geneve a|1#" = { ip_protocol = "udp", from_port = 6081, to_port = 6081, cidr_ipv4 = "10.20.1.0/28" }
      }
    }
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["geneve a|1#"].tags["Name"] == "Dev-app-mgmt-sg-in-geneve a1"
    error_message = "The key stays as it is in the address; only its use in the Name tag is cleaned (a space is allowed in a tag)"
  }
}

# The cut at 252 characters of the base "Dev-<key>": a hyphen interior to the base (before the cut), on the cut and after it.
run "naming_hyphen_inside_the_base_is_kept" {
  command = plan

  variables {
    userDefinedString = "${join("", [for i in range(246) : "a"])}-bbbb"
  }

  assert {
    condition     = aws_security_group.this.name == "Dev-${join("", [for i in range(246) : "a"])}-b-sg"
    error_message = "A hyphen before the cut stays, and the cut keeps 252 characters of the base"
  }
}

run "naming_hyphen_just_after_the_cut_leaves_the_base_whole" {
  command = plan

  variables {
    userDefinedString = "${join("", [for i in range(248) : "a"])}-bbbb"
  }

  assert {
    condition     = aws_security_group.this.name == "Dev-${join("", [for i in range(248) : "a"])}-sg"
    error_message = "A cut just before a hyphen leaves a base that needs no trim"
  }
}

run "naming_empty_env_and_a_leading_hyphen_in_the_key_leave_no_leading_hyphen" {
  command = plan

  variables {
    env               = ""
    userDefinedString = "-sg-web"
  }

  assert {
    condition     = aws_security_group.this.name == "sg0-web-sg"
    error_message = "The leading hyphens are trimmed first, then the sg- change is made"
  }
}
