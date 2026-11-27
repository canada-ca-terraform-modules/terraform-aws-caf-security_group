output "object" {
  description = "Returns the full aws_security_group resource object"
  value       = aws_security_group.this
  sensitive   = true
}

output "id" {
  description = "Returns the ID of the security group (sg-...)"
  value       = aws_security_group.this.id
}

output "arn" {
  description = "Returns the ARN of the security group"
  value       = aws_security_group.this.arn
}

output "name" {
  description = "Returns the name of the security group"
  value       = aws_security_group.this.name
}

output "vpc_id" {
  description = "Returns the ID of the VPC of the security group"
  value       = aws_security_group.this.vpc_id
}

output "owner_id" {
  description = "Returns the ID of the account that owns the security group"
  value       = aws_security_group.this.owner_id
}

output "ingress_rule_ids" {
  description = "Returns the ID of each standalone ingress rule, keyed as ingress_rules"
  value       = { for k, v in aws_vpc_security_group_ingress_rule.this : k => v.security_group_rule_id }
}

output "egress_rule_ids" {
  description = "Returns the ID of each standalone egress rule, keyed as egress_rules (allow-all-egress for allow_all_egress)"
  value       = { for k, v in aws_vpc_security_group_egress_rule.this : k => v.security_group_rule_id }
}
