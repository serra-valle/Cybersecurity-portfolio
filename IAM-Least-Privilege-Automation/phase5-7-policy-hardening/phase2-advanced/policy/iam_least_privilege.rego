package aegis.iam

# Detect exact wildcard Action values.
# IAM JSON can represent Action as either a string or an array.
has_wildcard_action(action) {
    action == "*"
}

has_wildcard_action(action) {
    action[_] == "*"
}

# Detect exact wildcard Resource values.
# IAM JSON can represent Resource as either a string or an array.
has_wildcard_resource(resource) {
    resource == "*"
}

has_wildcard_resource(resource) {
    resource[_] == "*"
}

# Reject an AWS managed IAM policy when an Allow statement grants
# wildcard Action and wildcard Resource together.
deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_policy"

    policy_string := rc.change.after.policy
    policy := json.unmarshal(policy_string)

    statement := policy.Statement[_]
    statement.Effect == "Allow"

    has_wildcard_action(statement.Action)
    has_wildcard_resource(statement.Resource)

    msg := sprintf(
        "DENY: IAM policy '%s' grants wildcard Action '*' on wildcard Resource '*'.",
        [rc.name],
    )
}
