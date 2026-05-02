package terraform.s3

import rego.v1

# Deny S3 buckets without server-side encryption configured
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.after != null
    not has_encryption(resource)
    msg := sprintf("S3 bucket '%s' does not have server-side encryption configured", [resource.address])
}

# Deny S3 buckets with public ACLs
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.after != null
    acl := resource.change.after.acl
    acl in {"public-read", "public-read-write", "authenticated-read"}
    msg := sprintf("S3 bucket '%s' has public ACL '%s'", [resource.address, acl])
}

# Deny S3 buckets without versioning enabled
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_versioning"
    resource.change.after != null
    config := resource.change.after.versioning_configuration
    some vc in config
    vc.status != "Enabled"
    msg := sprintf("S3 bucket versioning '%s' is not enabled", [resource.address])
}

# Deny S3 buckets without versioning resource at all
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.after != null
    not has_versioning_resource(resource.address)
    msg := sprintf("S3 bucket '%s' has no versioning configuration resource", [resource.address])
}

# Helper: check if encryption configuration exists
has_encryption(resource) if {
    some r in input.resource_changes
    r.type == "aws_s3_bucket_server_side_encryption_configuration"
    contains(r.address, resource.name)
}

has_encryption(resource) if {
    resource.change.after.server_side_encryption_configuration != null
}

# Helper: check if versioning resource exists for a bucket
has_versioning_resource(bucket_address) if {
    some r in input.resource_changes
    r.type == "aws_s3_bucket_versioning"
    contains(r.address, split(bucket_address, ".")[count(split(bucket_address, ".")) - 1])
}
