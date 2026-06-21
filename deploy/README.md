# Reference Harness Terraform Deployment Module

This module provisions the Google Cloud Platform (GCP) resources required to run
the Reference Harness security auditing engine in Enterprise Mode.

## Resources Managed

1.  **Google Service Account**: Dedicated runtime identity
    (`reference-harness-runner`) for executing scans under least-privilege.
1.  **Google Storage Bucket**: Unified storage bucket
    (`<project-id>-reference-harness-reports`) for uploading generated master
    reports.
1.  **IAM Bindings**:

- `roles/aiplatform.user` for Vertex AI model reasoning and playbooks discovery.
- `roles/storage.objectAdmin` for GCS bucket uploads and retrieval.
- `roles/logging.logWriter` for writing structured logs to Cloud Logging.

1.  **Google Cloud Run (v2)**: Exposes the Reference Harness FastAPI ASGI
    application, automatically scaling to handle remote scan requests securely.

## Usage

### 1. Authenticate with Google Cloud

Ensure you are logged into the target GCP project:

```bash
gcloud auth login
gcloud auth application-default login
```

### 2. Execute Terraform

Initialize the Terraform configuration and apply the plans:

```bash
terraform init
terraform apply \
    -var="project_id=your-target-gcp-project-id" \
    -var="region=us-central1" \
    -var="image_tag=latest"
```

### 3. Module Variables

| Variable               | Type     | Default       | Description                                                       |
| :--------------------- | :------- | :------------ | :---------------------------------------------------------------- |
| `project_id`           | `string` | _Required_    | GCP project ID to deploy into.                                    |
| `region`               | `string` | `us-central1` | GCP region for deployment.                                        |
| `image_tag`            | `string` | `latest`      | Container image tag of Reference Harness to pull.                 |
| `source_image_project` | `string` | `<required>`  | Project ID hosting the primary Reference Harness container image. |
| `source_repo`          | `string` | `rh`          | Artifact Registry repository name hosting the container.          |

### 4. Module Outputs

| Output            | Description                                                             |
| :---------------- | :---------------------------------------------------------------------- |
| `service_url`     | The HTTPS API endpoint URL of your Reference Harness Cloud Run service. |
| `service_account` | The email of the runtime service account.                               |
| `reports_bucket`  | The GCS bucket name allocated for consolidated master reports.          |
