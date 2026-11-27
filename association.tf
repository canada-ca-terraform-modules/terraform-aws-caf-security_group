## Associates the group with other VPCs (same Region), so that a rule of a group in another VPC can reference it.
resource "aws_vpc_security_group_vpc_association" "this" {
  for_each = try(var.security_group.vpc_associations, {})

  security_group_id = aws_security_group.this.id
  region            = try(coalesce(try(each.value.region, null), local.region), null)
  vpc_id            = try(each.value.vpc_id, null) != null ? each.value.vpc_id : lookup(var.vpc_ids, try(each.value.vpc_key, ""), null)

  dynamic "timeouts" {
    for_each = try(each.value.timeouts, null) != null ? [each.value.timeouts] : []
    content {
      create = try(timeouts.value.create, null)
      delete = try(timeouts.value.delete, null)
    }
  }

  lifecycle {
    precondition {
      condition     = length([for a in keys(each.value) : a if !contains(["vpc_id", "vpc_key", "region", "timeouts"], a)]) == 0
      error_message = "vpc_associations[\"${each.key}\"] has unknown keys: ${join(", ", [for a in keys(each.value) : a if !contains(["vpc_id", "vpc_key", "region", "timeouts"], a)])} (allowed: vpc_id, vpc_key, region, timeouts)."
    }
    precondition {
      condition     = try(each.value.vpc_id, null) != null || contains(keys(var.vpc_ids), try(each.value.vpc_key, ""))
      error_message = "vpc_associations[\"${each.key}\"] needs vpc_id, or a vpc_key present in vpc_ids (known: ${join(", ", keys(var.vpc_ids))})."
    }
  }
}
