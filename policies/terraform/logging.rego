package terraform.logging

import rego.v1

# Collect all VPC IDs that have flow logs configured
vpcs_with_flow_logs contains vpc_id if {
    some resource in input.resource_changes
    resource.type == "aws_flow_log"
    resource.change.after != null
    vpc_id := resource.change.after.vpc_id
}

# Deny VPCs without flow logs
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_vpc"
    resource.change.after != null
    resource.change.actions[_] in {"create", "update"}
    not resource_has_flow_log(resource)
    msg := sprintf("VPC '%s' does not have VPC Flow Logs enabled", [resource.address])
}

# Helper: check if a VPC resource has an associated flow log
resource_has_flow_log(vpc_resource) if {
    some fl in input.resource_changes
    fl.type == "aws_flow_log"
    fl.change.after != null
    # Match by reference - flow log references the VPC
    contains(fl.address, vpc_resource.name)
}

resource_has_flow_log(vpc_resource) if {
    # Check by explicit VPC ID if available
    some fl in input.resource_changes
    fl.type == "aws_flow_log"
    fl.change.after != null
    fl.change.after.vpc_id == vpc_resource.address
}
