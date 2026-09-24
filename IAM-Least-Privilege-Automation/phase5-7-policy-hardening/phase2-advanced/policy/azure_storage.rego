package aegis.azure.storage

# -------------------------------------------------------------------
# Azure Storage Account
#
# Prevent nested storage objects such as Blob containers from being
# configured for anonymous public access.
# -------------------------------------------------------------------

deny[msg] {
    changes := object.get(input, "resource_changes", [])

    account := changes[_]
    account.type == "azurerm_storage_account"

    change := object.get(account, "change", {})
    after := object.get(change, "after", null)
    after != null

    object.get(after, "allow_nested_items_to_be_public", true) != false

    msg := sprintf(
        "DENY: Azure Storage account '%s' allows nested items to be configured for public access.",
        [account.name],
    )
}

# -------------------------------------------------------------------
# Azure Storage infrastructure encryption
# -------------------------------------------------------------------

deny[msg] {
    changes := object.get(input, "resource_changes", [])

    account := changes[_]
    account.type == "azurerm_storage_account"

    change := object.get(account, "change", {})
    after := object.get(change, "after", null)
    after != null

    object.get(after, "infrastructure_encryption_enabled", false) != true

    msg := sprintf(
        "DENY: Azure Storage account '%s' does not have infrastructure encryption enabled.",
        [account.name],
    )
}

# -------------------------------------------------------------------
# Azure Blob container public access
# -------------------------------------------------------------------

deny[msg] {
    changes := object.get(input, "resource_changes", [])

    container := changes[_]
    container.type == "azurerm_storage_container"

    change := object.get(container, "change", {})
    after := object.get(change, "after", null)
    after != null

    object.get(after, "container_access_type", "") != "private"

    msg := sprintf(
        "DENY: Azure Storage container '%s' permits public blob or container access.",
        [container.name],
    )
}
