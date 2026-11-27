## Names follow Documentation/Standards/AWS-Naming-and-Tagging-Suffixes.md: <env>-<userDefinedString>-<suffix> (sg for the
## security group), letters, digits and hyphens, case kept.
## aws_security_group.name: at most 255 characters, [0-9A-Za-z._-:/()#,@[]+=&;{}!$*] (a space is allowed by AWS and left out
## here), and it may not start with "sg-" (AWS reserves it; the module treats the prefix as reserved whatever its case, which AWS
## does not document). The base is cut at 252 so that "<base>-sg" fits 255; "sg" at the start of the base, alone or before a
## hyphen, becomes "sg0" so that the name never starts with "sg-", and the cut can leave a hyphen, so the base is trimmed after it.
## A custom name has the "sg-" change made before the cut to 255, because the change adds a character.
## The Name tag is the group name without the characters a tag value does not allow (it takes letters, digits, spaces and
## _ . : / = + - @, up to 256 characters), so a custom name with a parenthesis or a "#" still gives a valid tag.
## The standalone rules carry a Name tag too, "<group Name tag>-in-<key>" or "-out-<key>", cleaned and cut to 256 the same way.
## The other resources (rules exclusive set, VPC associations) have no name and no tags: nothing is derived for them.
locals {
  name-regex     = "/[^0-9A-Za-z-]/"
  env-compliant  = replace(var.env, local.name-regex, "")
  name-compliant = replace(var.userDefinedString, local.name-regex, "")
  base-raw       = trim("${local.env-compliant}-${local.name-compliant}", "-")

  sg-regex           = "/[^0-9A-Za-z._:/()#,@\\[\\]+=&;{}!$*-]/"
  tag-regex          = "/[^0-9A-Za-z _.:/=+@-]/"
  sg-base-regex      = "/^((?i)sg)(-|$)/"
  sg-custom-regex    = "/^((?i)sg)-/"
  sg-base-replace    = "$${1}0$${2}"
  sg-custom-replace  = "$${1}0-"
  sg-base            = trim(substr(replace(local.base-raw, local.sg-base-regex, local.sg-base-replace), 0, 252), "-")
  sg-name-auto       = local.sg-base != "" ? "${local.sg-base}-sg" : "sg"
  sg-name-custom     = substr(replace(replace(try(coalesce(var.security_group.name), ""), local.sg-regex, ""), local.sg-custom-regex, local.sg-custom-replace), 0, 255)
  sg-name            = local.sg-name-custom != "" ? local.sg-name-custom : local.sg-name-auto
  sg-tag-name        = substr(replace(local.sg-name, local.tag-regex, ""), 0, 256)
  ingress-rule-names = { for k in keys(local.ingress-rules) : k => substr("${local.sg-tag-name}-in-${replace(k, local.tag-regex, "")}", 0, 256) }
  egress-rule-names  = { for k in keys(local.egress-rules) : k => substr("${local.sg-tag-name}-out-${replace(k, local.tag-regex, "")}", 0, 256) }
}
