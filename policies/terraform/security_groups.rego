package terraform.security_groups

import rego.v1

# Allowed ports for public ingress (0.0.0.0/0)
allowed_public_ports := {80, 443}

# Deny security group rules allowing ingress from 0.0.0.0/0 on non-standard ports
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    resource.change.after != null
    some rule in resource.change.after.ingress
    some cidr in rule.cidr_blocks
    cidr == "0.0.0.0/0"
    port := rule.from_port
    not port in allowed_public_ports
    msg := sprintf("Security group '%s' allows ingress from 0.0.0.0/0 on port %d (only ports 80, 443 allowed for public access)", [resource.address, port])
}

# Deny security group rules allowing ingress from ::/0 (IPv6 any) on non-standard ports
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    resource.change.after != null
    some rule in resource.change.after.ingress
    some cidr in rule.ipv6_cidr_blocks
    cidr == "::/0"
    port := rule.from_port
    not port in allowed_public_ports
    msg := sprintf("Security group '%s' allows IPv6 ingress from ::/0 on port %d (only ports 80, 443 allowed for public access)", [resource.address, port])
}

# Deny standalone security group rules allowing ingress from 0.0.0.0/0 on non-standard ports
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group_rule"
    resource.change.after != null
    resource.change.after.type == "ingress"
    some cidr in resource.change.after.cidr_blocks
    cidr == "0.0.0.0/0"
    port := resource.change.after.from_port
    not port in allowed_public_ports
    msg := sprintf("Security group rule '%s' allows ingress from 0.0.0.0/0 on port %d", [resource.address, port])
}

# Deny security groups with port range 0-65535 open to the internet
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    resource.change.after != null
    some rule in resource.change.after.ingress
    some cidr in rule.cidr_blocks
    cidr == "0.0.0.0/0"
    rule.from_port == 0
    rule.to_port == 65535
    msg := sprintf("Security group '%s' allows all ports (0-65535) from 0.0.0.0/0", [resource.address])
}
