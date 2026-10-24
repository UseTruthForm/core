# StackDNA's access to one Google Cloud project, written by
# "stackdna permissions --platform gcp" with its values in terraform.tfvars
# beside it. Apply grants it; destroy removes it.
#
# Keep this directory: the Terraform state in it is what destroy reads. If
# it is lost, the grants stay and must be removed by hand.

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

variable "project" {
  type        = string
  description = "The project StackDNA reads."
}

variable "member" {
  type        = string
  description = "Who runs StackDNA: user:..., serviceAccount:... or group:..."
}

variable "access" {
  type    = string
  default = "capture"
  validation {
    condition     = contains(["capture", "restore"], var.access)
    error_message = "access is capture or restore."
  }
}

locals {
  # Capture: viewer reads the resources, cloudasset.viewer lists them.
  # Viewer alone fails loudly: Cloud Asset Inventory answers 403.
  roles = var.access == "restore" ? [
    "roles/editor", "roles/iam.serviceAccountAdmin", "roles/iam.roleAdmin", "roles/cloudasset.viewer",
  ] : ["roles/viewer", "roles/cloudasset.viewer"]
}

provider "google" {
  project = var.project
}

# The APIs a capture lists through. disable_on_destroy is false because
# removing StackDNA's access must not switch off an API the project itself
# depends on.
resource "google_project_service" "stackdna" {
  for_each           = toset(["cloudasset.googleapis.com", "cloudresourcemanager.googleapis.com"])
  project            = var.project
  service            = each.value
  disable_on_destroy = false
}

# _member, not _binding: a binding owns the role's whole member list and
# would remove everyone else holding roles/viewer in the project.
resource "google_project_iam_member" "stackdna" {
  for_each = toset(local.roles)
  project  = var.project
  role     = each.value
  member   = var.member
}

output "roles" {
  value = sort(local.roles)
}
