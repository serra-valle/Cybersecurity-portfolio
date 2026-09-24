terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "5.4.0"
    }
  }
}

provider "azurerm" {
  features {}

  resource_provider_registrations = "none"
}

resource "azurerm_resource_group" "secure" {
  name     = "aegis-phase2-secure-rg"
  location = "West Europe"
}

resource "azurerm_storage_account" "secure" {
  name                     = "aegisph2secure987654"
  resource_group_name      = azurerm_resource_group.secure.name
  location                 = azurerm_resource_group.secure.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  allow_nested_items_to_be_public   = false
  infrastructure_encryption_enabled = true
  min_tls_version                   = "TLS1_2"
}

resource "azurerm_storage_container" "secure" {
  name                  = "private-data"
  storage_account_id    = azurerm_storage_account.secure.id
  container_access_type = "private"
}
