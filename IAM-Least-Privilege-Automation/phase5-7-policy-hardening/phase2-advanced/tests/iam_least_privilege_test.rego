package aegis.iam

test_allow_least_privilege_policy {
    input := {
        "resource_changes": [
            {
                "type": "aws_iam_policy",
                "name": "least_privilege",
                "change": {
                    "after": {
                        "policy": "{\"Statement\":[{\"Action\":\"s3:GetObject\",\"Effect\":\"Allow\",\"Resource\":\"arn:aws:s3:::aegis-example-bucket/*\"}],\"Version\":\"2012-10-17\"}"
                    }
                }
            }
        ]
    }

    result := deny with input as input
    count(result) == 0
}

test_deny_wildcard_action_and_resource {
    input := {
        "resource_changes": [
            {
                "type": "aws_iam_policy",
                "name": "wildcard_policy",
                "change": {
                    "after": {
                        "policy": "{\"Statement\":[{\"Action\":\"*\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
                    }
                }
            }
        ]
    }

    result := deny with input as input
    count(result) > 0
}

test_allow_wildcard_resource_with_restricted_action {
    input := {
        "resource_changes": [
            {
                "type": "aws_iam_policy",
                "name": "restricted_action",
                "change": {
                    "after": {
                        "policy": "{\"Statement\":[{\"Action\":\"s3:GetObject\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
                    }
                }
            }
        ]
    }

    result := deny with input as input
    count(result) == 0
}

test_allow_wildcard_action_with_restricted_resource {
    input := {
        "resource_changes": [
            {
                "type": "aws_iam_policy",
                "name": "restricted_resource",
                "change": {
                    "after": {
                        "policy": "{\"Statement\":[{\"Action\":\"*\",\"Effect\":\"Allow\",\"Resource\":\"arn:aws:s3:::aegis-example-bucket/*\"}],\"Version\":\"2012-10-17\"}"
                    }
                }
            }
        ]
    }

    result := deny with input as input
    count(result) == 0
}

test_deny_wildcards_inside_arrays {
    input := {
        "resource_changes": [
            {
                "type": "aws_iam_policy",
                "name": "array_wildcards",
                "change": {
                    "after": {
                        "policy": "{\"Statement\":[{\"Action\":[\"s3:GetObject\",\"*\"],\"Effect\":\"Allow\",\"Resource\":[\"arn:aws:s3:::example/*\",\"*\"]}],\"Version\":\"2012-10-17\"}"
                    }
                }
            }
        ]
    }

    result := deny with input as input
    count(result) > 0
}

test_allow_deny_statement_with_wildcards {
    input := {
        "resource_changes": [
            {
                "type": "aws_iam_policy",
                "name": "explicit_deny",
                "change": {
                    "after": {
                        "policy": "{\"Statement\":[{\"Action\":\"*\",\"Effect\":\"Deny\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
                    }
                }
            }
        ]
    }

    result := deny with input as input
    count(result) == 0
}
