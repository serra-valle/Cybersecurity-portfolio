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

resource "azurerm_resource_group" "insecure" {
  name     = "aegis-phase2-insecure-rg"
  location = "West Europe"
}

resource "azurerm_storage_account" "insecure" {
  name                     = "aegisph2insecure98765"
  resource_group_name      = azurerm_resource_group.insecure.name
  location                 = azurerm_resource_group.insecure.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  allow_nested_items_to_be_public   = true
  infrastructure_encryption_enabled = false
}

resource "azurerm_storage_container" "insecure" {
  name                  = "public-data"
  storage_account_id    = azurerm_storage_account.insecure.id
  container_access_type = "blob"
}
