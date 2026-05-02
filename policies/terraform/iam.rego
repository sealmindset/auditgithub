package terraform.iam

import rego.v1

# Deny IAM policies with wildcard actions on Allow statements
deny contains msg if {
    some resource in input.resource_changes
    resource.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
    resource.change.after != null
    policy_doc := resource.change.after.policy
    doc := json.unmarshal(policy_doc)
    some statement in doc.Statement
    statement.Effect == "Allow"
    some action in to_array(statement.Action)
    action == "*"
    msg := sprintf("IAM policy '%s' contains wildcard action (*) on Allow statement", [resource.address])
}

# Deny IAM policies with wildcard resources on Allow statements
deny contains msg if {
    some resource in input.resource_changes
    resource.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
    resource.change.after != null
    policy_doc := resource.change.after.policy
    doc := json.unmarshal(policy_doc)
    some statement in doc.Statement
    statement.Effect == "Allow"
    some res in to_array(statement.Resource)
    res == "*"
    some action in to_array(statement.Action)
    action != "*"
    msg := sprintf("IAM policy '%s' grants action '%s' on wildcard resource (*)", [resource.address, action])
}

# Deny IAM policies with both wildcard action and wildcard resource (admin access)
deny contains msg if {
    some resource in input.resource_changes
    resource.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
    resource.change.after != null
    policy_doc := resource.change.after.policy
    doc := json.unmarshal(policy_doc)
    some statement in doc.Statement
    statement.Effect == "Allow"
    some action in to_array(statement.Action)
    action == "*"
    some res in to_array(statement.Resource)
    res == "*"
    msg := sprintf("IAM policy '%s' grants full admin access (*:*) - this is a critical security risk", [resource.address])
}

# Helper: normalize to array
to_array(x) := [x] if {
    is_string(x)
}

to_array(x) := x if {
    is_array(x)
}
