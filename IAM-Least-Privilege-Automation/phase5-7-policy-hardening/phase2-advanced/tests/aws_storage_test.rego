package aegis.aws.storage

secure_storage_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.application_logs",
                    "type": "aws_s3_bucket",
                    "expressions": {}
                },
                {
                    "address": "aws_s3_bucket_public_access_block.bucket_guard",
                    "type": "aws_s3_bucket_public_access_block",
                    "expressions": {
                        "bucket": {
                            "references": [
                                "aws_s3_bucket.application_logs.id",
                                "aws_s3_bucket.application_logs"
                            ]
                        }
                    }
                },
                {
                    "address": "aws_s3_bucket_server_side_encryption_configuration.bucket_crypto",
                    "type": "aws_s3_bucket_server_side_encryption_configuration",
                    "expressions": {
                        "bucket": {
                            "references": [
                                "aws_s3_bucket.application_logs.id",
                                "aws_s3_bucket.application_logs"
                            ]
                        }
                    }
                }
            ]
        }
    },
    "resource_changes": [
        {
            "address": "aws_s3_bucket.application_logs",
            "type": "aws_s3_bucket",
            "name": "application_logs",
            "change": {
                "after": {
                    "bucket": "application-logs"
                }
            }
        },
        {
            "address": "aws_s3_bucket_public_access_block.bucket_guard",
            "type": "aws_s3_bucket_public_access_block",
            "name": "bucket_guard",
            "change": {
                "after": {
                    "block_public_acls": true,
                    "block_public_policy": true,
                    "ignore_public_acls": true,
                    "restrict_public_buckets": true
                }
            }
        },
        {
            "address": "aws_s3_bucket_server_side_encryption_configuration.bucket_crypto",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "name": "bucket_crypto",
            "change": {
                "after": {
                    "rule": [
                        {
                            "apply_server_side_encryption_by_default": [
                                {
                                    "sse_algorithm": "AES256"
                                }
                            ]
                        }
                    ]
                }
            }
        },
        {
            "address": "aws_ebs_volume.secure",
            "type": "aws_ebs_volume",
            "name": "secure",
            "change": {
                "after": {
                    "encrypted": true
                }
            }
        },
        {
            "address": "aws_db_instance.secure",
            "type": "aws_db_instance",
            "name": "secure",
            "change": {
                "after": {
                    "storage_encrypted": true
                }
            }
        }
    ]
}

test_secure_storage_passes {
    result := deny with input as secure_storage_input
    count(result) == 0
}

insecure_storage_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.insecure",
                    "type": "aws_s3_bucket",
                    "expressions": {}
                },
                {
                    "address": "aws_s3_bucket_public_access_block.insecure_guard",
                    "type": "aws_s3_bucket_public_access_block",
                    "expressions": {
                        "bucket": {
                            "references": [
                                "aws_s3_bucket.insecure.id",
                                "aws_s3_bucket.insecure"
                            ]
                        }
                    }
                }
            ]
        }
    },
    "resource_changes": [
        {
            "address": "aws_s3_bucket.insecure",
            "type": "aws_s3_bucket",
            "name": "insecure",
            "change": {
                "after": {}
            }
        },
        {
            "address": "aws_s3_bucket_public_access_block.insecure_guard",
            "type": "aws_s3_bucket_public_access_block",
            "name": "insecure_guard",
            "change": {
                "after": {
                    "block_public_acls": false,
                    "block_public_policy": false,
                    "ignore_public_acls": false,
                    "restrict_public_buckets": false
                }
            }
        },
        {
            "address": "aws_ebs_volume.insecure",
            "type": "aws_ebs_volume",
            "name": "insecure",
            "change": {
                "after": {
                    "encrypted": false
                }
            }
        },
        {
            "address": "aws_db_instance.insecure",
            "type": "aws_db_instance",
            "name": "insecure",
            "change": {
                "after": {
                    "storage_encrypted": false
                }
            }
        }
    ]
}

test_insecure_storage_returns_four_denials {
    result := deny with input as insecure_storage_input
    count(result) == 4
}

missing_public_access_block_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.no_guard",
                    "type": "aws_s3_bucket",
                    "expressions": {}
                },
                {
                    "address": "aws_s3_bucket_server_side_encryption_configuration.no_guard_crypto",
                    "type": "aws_s3_bucket_server_side_encryption_configuration",
                    "expressions": {
                        "bucket": {
                            "references": [
                                "aws_s3_bucket.no_guard"
                            ]
                        }
                    }
                }
            ]
        }
    },
    "resource_changes": [
        {
            "address": "aws_s3_bucket.no_guard",
            "type": "aws_s3_bucket",
            "name": "no_guard",
            "change": {
                "after": {}
            }
        },
        {
            "address": "aws_s3_bucket_server_side_encryption_configuration.no_guard_crypto",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "name": "no_guard_crypto",
            "change": {
                "after": {
                    "rule": [
                        {
                            "apply_server_side_encryption_by_default": [
                                {
                                    "sse_algorithm": "AES256"
                                }
                            ]
                        }
                    ]
                }
            }
        }
    ]
}

test_missing_s3_public_access_block_is_denied {
    result := deny with input as missing_public_access_block_input
    count(result) == 1
}

partial_public_access_block_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.partial",
                    "type": "aws_s3_bucket",
                    "expressions": {}
                },
                {
                    "address": "aws_s3_bucket_public_access_block.partial_guard",
                    "type": "aws_s3_bucket_public_access_block",
                    "expressions": {
                        "bucket": {
                            "references": [
                                "aws_s3_bucket.partial"
                            ]
                        }
                    }
                },
                {
                    "address": "aws_s3_bucket_server_side_encryption_configuration.partial_crypto",
                    "type": "aws_s3_bucket_server_side_encryption_configuration",
                    "expressions": {
                        "bucket": {
                            "references": [
                                "aws_s3_bucket.partial"
                            ]
                        }
                    }
                }
            ]
        }
    },
    "resource_changes": [
        {
            "address": "aws_s3_bucket.partial",
            "type": "aws_s3_bucket",
            "name": "partial",
            "change": {
                "after": {}
            }
        },
        {
            "address": "aws_s3_bucket_public_access_block.partial_guard",
            "type": "aws_s3_bucket_public_access_block",
            "name": "partial_guard",
            "change": {
                "after": {
                    "block_public_acls": true,
                    "block_public_policy": true,
                    "ignore_public_acls": false,
                    "restrict_public_buckets": false
                }
            }
        },
        {
            "address": "aws_s3_bucket_server_side_encryption_configuration.partial_crypto",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "name": "partial_crypto",
            "change": {
                "after": {
                    "rule": [
                        {
                            "apply_server_side_encryption_by_default": [
                                {
                                    "sse_algorithm": "AES256"
                                }
                            ]
                        }
                    ]
                }
            }
        }
    ]
}

test_partial_s3_public_access_block_is_denied {
    result := deny with input as partial_public_access_block_input
    count(result) == 1
}

missing_encryption_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.no_crypto",
                    "type": "aws_s3_bucket",
                    "expressions": {}
                },
                {
                    "address": "aws_s3_bucket_public_access_block.no_crypto_guard",
                    "type": "aws_s3_bucket_public_access_block",
                    "expressions": {
                        "bucket": {
                            "references": [
                                "aws_s3_bucket.no_crypto"
                            ]
                        }
                    }
                }
            ]
        }
    },
    "resource_changes": [
        {
            "address": "aws_s3_bucket.no_crypto",
            "type": "aws_s3_bucket",
            "name": "no_crypto",
            "change": {
                "after": {}
            }
        },
        {
            "address": "aws_s3_bucket_public_access_block.no_crypto_guard",
            "type": "aws_s3_bucket_public_access_block",
            "name": "no_crypto_guard",
            "change": {
                "after": {
                    "block_public_acls": true,
                    "block_public_policy": true,
                    "ignore_public_acls": true,
                    "restrict_public_buckets": true
                }
            }
        }
    ]
}

test_missing_s3_encryption_is_denied {
    result := deny with input as missing_encryption_input
    count(result) == 1
}
