package aegis.azure.storage

secure_azure_storage_input := {
    "resource_changes": [
        {
            "address": "azurerm_storage_account.secure",
            "type": "azurerm_storage_account",
            "name": "secure",
            "change": {
                "after": {
                    "allow_nested_items_to_be_public": false,
                    "infrastructure_encryption_enabled": true
                }
            }
        },
        {
            "address": "azurerm_storage_container.secure",
            "type": "azurerm_storage_container",
            "name": "secure",
            "change": {
                "after": {
                    "container_access_type": "private"
                }
            }
        }
    ]
}

test_secure_azure_storage_passes {
    result := deny with input as secure_azure_storage_input
    count(result) == 0
}


insecure_azure_storage_input := {
    "resource_changes": [
        {
            "address": "azurerm_storage_account.insecure",
            "type": "azurerm_storage_account",
            "name": "insecure",
            "change": {
                "after": {
                    "allow_nested_items_to_be_public": true,
                    "infrastructure_encryption_enabled": false
                }
            }
        },
        {
            "address": "azurerm_storage_container.insecure",
            "type": "azurerm_storage_container",
            "name": "insecure",
            "change": {
                "after": {
                    "container_access_type": "blob"
                }
            }
        }
    ]
}

test_insecure_azure_storage_returns_three_denials {
    result := deny with input as insecure_azure_storage_input
    count(result) == 3
}


public_nested_items_input := {
    "resource_changes": [
        {
            "address": "azurerm_storage_account.public_nested",
            "type": "azurerm_storage_account",
            "name": "public_nested",
            "change": {
                "after": {
                    "allow_nested_items_to_be_public": true,
                    "infrastructure_encryption_enabled": true
                }
            }
        }
    ]
}

test_public_nested_items_are_denied {
    result := deny with input as public_nested_items_input
    count(result) == 1
}


unencrypted_storage_input := {
    "resource_changes": [
        {
            "address": "azurerm_storage_account.no_infra_encryption",
            "type": "azurerm_storage_account",
            "name": "no_infra_encryption",
            "change": {
                "after": {
                    "allow_nested_items_to_be_public": false,
                    "infrastructure_encryption_enabled": false
                }
            }
        }
    ]
}

test_missing_infrastructure_encryption_is_denied {
    result := deny with input as unencrypted_storage_input
    count(result) == 1
}


public_container_input := {
    "resource_changes": [
        {
            "address": "azurerm_storage_container.public_blob",
            "type": "azurerm_storage_container",
            "name": "public_blob",
            "change": {
                "after": {
                    "container_access_type": "blob"
                }
            }
        }
    ]
}

test_public_blob_container_is_denied {
    result := deny with input as public_container_input
    count(result) == 1
}
