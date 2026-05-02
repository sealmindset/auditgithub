package terraform.networking

import rego.v1

# Deny subnets with automatic public IP assignment
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_subnet"
    resource.change.after != null
    resource.change.after.map_public_ip_on_launch == true
    msg := sprintf("Subnet '%s' has map_public_ip_on_launch enabled - instances will receive public IPs automatically", [resource.address])
}

# Deny default route tables with routes to internet gateways (prefer explicit route tables)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_default_route_table"
    resource.change.after != null
    some route in resource.change.after.route
    route.gateway_id != null
    route.gateway_id != ""
    msg := sprintf("Default route table '%s' has a route to an internet gateway - use explicit route tables for better control", [resource.address])
}
