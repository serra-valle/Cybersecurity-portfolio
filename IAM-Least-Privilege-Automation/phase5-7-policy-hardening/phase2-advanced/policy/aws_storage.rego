package aegis.aws.storage

# -------------------------------------------------------------------
# Terraform configuration helpers
# -------------------------------------------------------------------

# Determine whether a configuration resource references a target
# Terraform resource through its "bucket" expression.
#
# Example:
# aws_s3_bucket_public_access_block.logs_guard
#     -> aws_s3_bucket.application_logs.id
#
# All arguments passed to this helper are already bound by the caller.
config_resource_references(config_address, resource_type, target_address) {
    configuration := object.get(input, "configuration", {})
    root_module := object.get(configuration, "root_module", {})
    resources := object.get(root_module, "resources", [])

    resource := resources[_]
    resource.address == config_address
    resource.type == resource_type

    expressions := object.get(resource, "expressions", {})
    bucket_expression := object.get(expressions, "bucket", {})
    references := object.get(bucket_expression, "references", [])

    reference := references[_]
    reference == target_address
}

config_resource_references(config_address, resource_type, target_address) {
    configuration := object.get(input, "configuration", {})
    root_module := object.get(configuration, "root_module", {})
    resources := object.get(root_module, "resources", [])

    resource := resources[_]
    resource.address == config_address
    resource.type == resource_type

    expressions := object.get(resource, "expressions", {})
    bucket_expression := object.get(expressions, "bucket", {})
    references := object.get(bucket_expression, "references", [])

    reference := references[_]
    startswith(reference, sprintf("%s.", [target_address]))
}

# -------------------------------------------------------------------
# S3 server-side encryption
# -------------------------------------------------------------------

valid_s3_encryption(target_address) {
    changes := object.get(input, "resource_changes", [])

    encryption := changes[_]
    encryption.type == "aws_s3_bucket_server_side_encryption_configuration"

    config_resource_references(
        encryption.address,
        "aws_s3_bucket_server_side_encryption_configuration",
        target_address,
    )

    change := object.get(encryption, "change", {})
    after := object.get(change, "after", null)
    after != null

    rules := object.get(after, "rule", [])
    rule := rules[_]

    defaults := object.get(
        rule,
        "apply_server_side_encryption_by_default",
        [],
    )

    encryption_default := defaults[_]
    algorithm := object.get(encryption_default, "sse_algorithm", "")
    algorithm != ""
}

# -------------------------------------------------------------------
# S3 Public Access Block
#
# Aegis hardened baseline:
#   block_public_acls       = true
#   block_public_policy     = true
#   ignore_public_acls      = true
#   restrict_public_buckets = true
# -------------------------------------------------------------------

hardened_s3_public_access_block(target_address) {
    changes := object.get(input, "resource_changes", [])

    public_access_block := changes[_]
    public_access_block.type == "aws_s3_bucket_public_access_block"

    config_resource_references(
        public_access_block.address,
        "aws_s3_bucket_public_access_block",
        target_address,
    )

    change := object.get(public_access_block, "change", {})
    after := object.get(change, "after", null)
    after != null

    object.get(after, "block_public_acls", false) == true
    object.get(after, "block_public_policy", false) == true
    object.get(after, "ignore_public_acls", false) == true
    object.get(after, "restrict_public_buckets", false) == true
}

# -------------------------------------------------------------------
# S3 enforcement
# -------------------------------------------------------------------

deny[msg] {
    changes := object.get(input, "resource_changes", [])

    bucket := changes[_]
    bucket.type == "aws_s3_bucket"

    change := object.get(bucket, "change", {})
    after := object.get(change, "after", null)
    after != null

    not valid_s3_encryption(bucket.address)

    msg := sprintf(
        "DENY: S3 bucket '%s' does not have an explicit server-side encryption configuration.",
        [bucket.name],
    )
}

deny[msg] {
    changes := object.get(input, "resource_changes", [])

    bucket := changes[_]
    bucket.type == "aws_s3_bucket"

    change := object.get(bucket, "change", {})
    after := object.get(change, "after", null)
    after != null

    not hardened_s3_public_access_block(bucket.address)

    msg := sprintf(
        "DENY: S3 bucket '%s' does not have all required Public Access Block protections enabled.",
        [bucket.name],
    )
}

# -------------------------------------------------------------------
# EBS encryption
# -------------------------------------------------------------------

deny[msg] {
    changes := object.get(input, "resource_changes", [])

    volume := changes[_]
    volume.type == "aws_ebs_volume"

    change := object.get(volume, "change", {})
    after := object.get(change, "after", null)
    after != null

    object.get(after, "encrypted", false) != true

    msg := sprintf(
        "DENY: EBS volume '%s' is not explicitly encrypted.",
        [volume.name],
    )
}

# -------------------------------------------------------------------
# RDS storage encryption
# -------------------------------------------------------------------

deny[msg] {
    changes := object.get(input, "resource_changes", [])

    database := changes[_]
    database.type == "aws_db_instance"

    change := object.get(database, "change", {})
    after := object.get(change, "after", null)
    after != null

    object.get(after, "storage_encrypted", false) != true

    msg := sprintf(
        "DENY: RDS instance '%s' does not have storage encryption enabled.",
        [database.name],
    )
}
