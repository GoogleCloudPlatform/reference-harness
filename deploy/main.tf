# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

provider "google" {
  project = var.project_id
  region  = var.region
}

# Service Account
resource "google_service_account" "vulncatcher" {
  account_id   = "vulncatcher-runner"
  display_name = "VulnCatcher Runtime"
}

# Reports Bucket
resource "google_storage_bucket" "reports" {
  name                        = "${var.project_id}-vulncatcher-reports"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = false
}

# IAM: Vertex AI User
resource "google_project_iam_member" "vertex_ai" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.vulncatcher.email}"
}

# IAM: Cloud Storage Object Admin
resource "google_project_iam_member" "storage" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.vulncatcher.email}"
}

# IAM: Cloud Logging Writer
resource "google_project_iam_member" "logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vulncatcher.email}"
}

# Cloud Run Service
resource "google_cloud_run_v2_service" "vulncatcher" {
  name     = "vulncatcher"
  location = var.region

  template {
    service_account = google_service_account.vulncatcher.email

    containers {
      image = "${var.region}-docker.pkg.dev/${var.source_image_project}/${var.source_repo}/vulncatcher:${var.image_tag}"

      resources {
        limits = {
          cpu    = "2"
          memory = "4Gi"
        }
      }

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "LOGS_BUCKET_NAME"
        value = google_storage_bucket.reports.name
      }
    }

    timeout                          = "3600s"
    max_instance_request_concurrency = 1

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }
  }
}
