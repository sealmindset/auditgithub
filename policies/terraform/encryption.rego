package terraform.encryption

import rego.v1

# Deny RDS instances without encryption at rest
deny contains msg if {
    some resource in input.resource_changes
    resource.type in {"aws_db_instance", "aws_rds_cluster"}
    resource.change.after != null
    not resource.change.after.storage_encrypted
    msg := sprintf("RDS resource '%s' does not have storage encryption enabled", [resource.address])
}

# Deny RDS instances without encryption explicitly set (defaults to false)
deny contains msg if {
    some resource in input.resource_changes
    resource.type in {"aws_db_instance", "aws_rds_cluster"}
    resource.change.after != null
    resource.change.after.storage_encrypted == null
    msg := sprintf("RDS resource '%s' does not explicitly configure storage encryption (defaults to disabled)", [resource.address])
}

# Deny EBS volumes without encryption
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_ebs_volume"
    resource.change.after != null
    not resource.change.after.encrypted
    msg := sprintf("EBS volume '%s' does not have encryption enabled", [resource.address])
}

# Deny EBS volumes with encryption not explicitly set
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_ebs_volume"
    resource.change.after != null
    resource.change.after.encrypted == null
    msg := sprintf("EBS volume '%s' does not explicitly configure encryption (defaults to disabled)", [resource.address])
}

# Deny launch templates with unencrypted EBS block devices
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_launch_template"
    resource.change.after != null
    some bd in resource.change.after.block_device_mappings
    bd.ebs != null
    not bd.ebs.encrypted
    msg := sprintf("Launch template '%s' has unencrypted EBS block device mapping", [resource.address])
}

# Deny Elasticsearch/OpenSearch domains without encryption at rest
deny contains msg if {
    some resource in input.resource_changes
    resource.type in {"aws_elasticsearch_domain", "aws_opensearch_domain"}
    resource.change.after != null
    not encryption_at_rest_enabled(resource)
    msg := sprintf("Elasticsearch/OpenSearch domain '%s' does not have encryption at rest enabled", [resource.address])
}

# Helper: check encryption at rest configuration
encryption_at_rest_enabled(resource) if {
    resource.change.after.encrypt_at_rest[_].enabled == true
}
