# The three security groups of a network appliance with several interfaces: management, private and public.
# A rule names exactly one source: cidr_ipv4, cidr_ipv6, prefix_list_id/prefix_list_key, referenced_security_group_id/referenced_security_group_key or self = true.
security_groups = {
  app-mgmt = {                                     # Key defines the userDefinedString; the group name is "<env>-app-mgmt-sg"
    vpc_key     = "Main"                           # Required (or vpc_id): key of the vpc_ids lookup map; neither is rejected
    description = "Appliance management interface" # Optional: Default: "Managed by Terraform"; 1 to 255 characters; a change replaces the group
    # name = "my-custom-name"                     # Optional: overrides the auto-derived "<env>-app-mgmt-sg" name

    # --- rules.tf: standalone rules, one per entry ---
    ingress_rules = {
      ssh = {
        ip_protocol = "tcp"                           # Required: tcp, udp, icmp, icmpv6, a protocol number from 0 to 255, or "-1" (all)
        from_port   = 22                              # tcp/udp: first port (0 to 65535); icmp: type (-1 for all). Not with "-1"
        to_port     = 22                              # tcp/udp: last port, not below from_port; icmp: code (-1 for all). Not with "-1"
        cidr_ipv4   = "10.10.0.0/24"                  # Source range: the management range
        description = "SSH from the management range" # Optional: description of the rule
      }
      https = {
        ip_protocol = "tcp"                             # HTTPS is TCP
        from_port   = 443                               # HTTPS port
        to_port     = 443                               # HTTPS port
        cidr_ipv4   = "10.10.0.0/24"                    # Source range: the management range
        description = "HTTPS from the management range" # Optional: description of the rule
      }
    }
    egress_rules = {
      s3 = {
        ip_protocol     = "tcp"                                             # HTTPS to the configuration bucket is TCP
        from_port       = 443                                               # HTTPS port
        to_port         = 443                                               # HTTPS port
        prefix_list_key = "s3"                                              # Key of the prefix_list_ids lookup map (the S3 gateway endpoint); or a literal prefix_list_id
        description     = "Configuration bucket through the S3 prefix list" # Optional: description of the rule
      }
    }
  }

  app-private = {
    vpc_key     = "Main"                                                  # Key of the vpc_ids lookup map
    description = "Appliance private interface (GENEVE and health check)" # Optional: description of the group
    ingress_rules = {
      geneve-1a = {
        ip_protocol = "udp"                                   # GENEVE is UDP
        from_port   = 6081                                    # GENEVE port
        to_port     = 6081                                    # GENEVE port
        cidr_ipv4   = "10.20.1.0/28"                          # GWLB subnet of zone a (example range)
        description = "GENEVE from the GWLB subnet of zone a" # Optional: description of the rule
      }
      geneve-1b = {
        ip_protocol = "udp"                                   # GENEVE is UDP
        from_port   = 6081                                    # GENEVE port
        to_port     = 6081                                    # GENEVE port
        cidr_ipv4   = "10.20.1.16/28"                         # GWLB subnet of zone b (example range)
        description = "GENEVE from the GWLB subnet of zone b" # Optional: description of the rule
      }
      health = {
        ip_protocol = "tcp"                                         # The health check is TCP
        from_port   = 443                                           # Health check port
        to_port     = 443                                           # Health check port
        cidr_ipv4   = "10.20.1.0/28"                                # GWLB subnet of zone a (example range)
        description = "Health check from the GWLB subnet of zone a" # Optional: description of the rule
      }
      # peer = {
      #   ip_protocol                   = "tcp"        # TCP
      #   from_port                     = 443          # Port
      #   to_port                       = 443          # Port
      #   referenced_security_group_key = "Main-gwlb" # A group made elsewhere: key of the security_group_ids lookup map
      # }
    }
    allow_all_egress = true # Optional: Default: false. One egress rule, every protocol to 0.0.0.0/0 (the provider removes the default allow-all rule)
  }

  app-public = {
    vpc_key          = "Main"                                    # Key of the vpc_ids lookup map
    description      = "Appliance public interface (no inbound)" # Optional: description of the group
    allow_all_egress = true                                      # No ingress_rules: nothing is admitted inbound
  }

  # Every other key of the object, shown on one group:
  # Example = {
  #   vpc_id                 = "vpc-0123456789abcdef0" # Literal VPC ID, wins over vpc_key
  #   region                 = "ca-central-1"          # Optional: region of the group and of every resource below. Default: the provider's region
  #   revoke_rules_on_delete = true                    # Optional: remove the rules before the group is deleted (circular references between groups)
  #   timeouts               = { create = "10m", delete = "15m" } # Optional: create and delete timeouts of the group
  #   tags = {                                         # Optional: merged with ESLZ-level tags; the Name tag follows the naming standard
  #     owner = "team-x"                               # A tag key and its value
  #   }
  #
  #   # --- rules.tf: more rule keys; the region of a rule defaults to the one above ---
  #   ingress_rules = {
  #     cluster = {
  #       ip_protocol = "-1"                           # Every protocol and port (no from_port or to_port)
  #       self        = true                           # The source is this group: its own members
  #       description = "Members of this group"        # Optional: description of the rule
  #     }
  #     peer = {
  #       ip_protocol                  = "tcp"                    # TCP
  #       from_port                    = 443                      # Port
  #       to_port                      = 443                      # Port
  #       referenced_security_group_id = "sg-0123456789abcdef0"   # Literal ID of the source group, wins over referenced_security_group_key
  #       tags                         = { purpose = "peer" }     # Optional: merged with the group's tags
  #       region                       = "ca-central-1"           # Optional: region of the rule. Default: the one of the group
  #     }
  #   }
  #   rules_exclusive = {} # Optional: the rules above become the only rules of the group (`{ region = "..." }` to set a region). Not with inline rules
  #
  #   # --- association.tf: the group also usable in other VPCs of the Region ---
  #   vpc_associations = {
  #     spoke = {
  #       vpc_key  = "Spoke"                           # Key of the vpc_ids lookup map; or vpc_id
  #       timeouts = { create = "5m", delete = "5m" }  # Optional: create and delete timeouts of the association
  #     }
  #   }
  #
  #   # --- module.tf: inline rules (legacy). Not with ingress_rules, egress_rules, allow_all_egress or rules_exclusive ---
  #   inline_ingress_rules = [{
  #     protocol    = "tcp"                            # tcp, udp, icmp, icmpv6, a number, or "-1"
  #     from_port   = 22                               # First port
  #     to_port     = 22                               # Last port
  #     cidr_blocks = ["10.10.0.0/24"]                 # Source ranges (also ipv6_cidr_blocks, prefix_list_ids, security_groups, self, description)
  #   }]
  #   inline_egress_rules = []                         # An empty list removes every egress rule, the default one included
  # }
}
