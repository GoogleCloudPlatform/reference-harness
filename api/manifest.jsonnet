local modules = import 'modules';
local spellcraft = import 'spellcraft';

local settings = import 'settings.jsonnet';

local gcp = import '@c6fc/spellcraft-gcp-terraform/module.libsonnet';
local normalize(name) = std.native('@c6fc/spellcraft-gcp-terraform:normalizeResourceName')(name);
local shorthash(name) = std.native('@c6fc/spellcraft-gcp-terraform:shortHash')(std.manifestJsonEx(name, ''));

local serviceList = [
  'artifactregistry.googleapis.com',
  'cloudbuild.googleapis.com',
  'cloudidentity.googleapis.com',
  'cloudresourcemanager.googleapis.com',
  'compute.googleapis.com',
  'iam.googleapis.com',
  'iap.googleapis.com',
  'run.googleapis.com',
  'serviceusage.googleapis.com',
];

local requiredServices = gcp.auth.enableServices(serviceList);

local metadata = gcp.auth.getProjectMetadata();

if !requiredServices then error 'Failed to enable services' else {
  'api-source.tf.json': {
    data: {
      archive_file: {
        api_source: {
          source_dir: '${path.module}/../cloud_run_functions/api/',
          output_path: '${path.module}/../cloud_run_functions/zip_files/api.tar.gz',
          type: 'tar.gz',
          depends_on: ['null_resource.npm_install_api'],
        },
      },
    },
    resource: {
      google_storage_bucket: {
        source: {
          name: std.format('vulncatcher-api-source-%s', shorthash(metadata)),
          location: settings.region,
          force_destroy: true,
          uniform_bucket_level_access: true,
        },
        reports: {
          name: std.format('vulncatcher-api-reports-%s', shorthash(metadata)),
          location: settings.region,
          force_destroy: true,
          uniform_bucket_level_access: true,
        },
      },
      google_storage_bucket_object: {
        source_tar: {
          name: 'api.tar.gz',
          bucket: '${google_storage_bucket.source.name}',
          source: '${data.archive_file.api_source.output_path}',
        },
      },
      null_resource: {
        npm_install_api: {
          provisioner: [{
            'local-exec': {
              command: 'cd ${path.module}/../cloud_run_functions/api/ && npm i',
            },
          }],
          triggers: {
            on_dockerfile_change: '${filebase64sha256("${path.module}/../../Dockerfile")}',
          },
        },
      },
    },
  },
  'cloud_run.tf.json': {
    resource: {
      google_artifact_registry_repository: {
        vulncatcher_repo: {
          project: metadata.projectId,
          format: 'DOCKER',
          repository_id: 'vulncatcher-docker',
          location: settings.region,
          description: 'Docker repository for VulnCatcher Container',
          depends_on: ['terraform_data.service_deps'],
        },
      },
      null_resource: {
        build_image: {
          provisioner: [{
            'local-exec': {
              command: 'bash ${path.module}/../submit_build.sh ${google_artifact_registry_repository.vulncatcher_repo.registry_uri}/vulncatcher-container:latest',
            },
          }],
          triggers: {
            on_dockerfile_change: '${filebase64sha256("${path.module}/../../Dockerfile")}',
          },
          depends_on: ['terraform_data.service_deps', 'terraform_data.builder_privilege_deps', 'local_file.entrypoint_script'],
        },
      },
      google_service_account: {
        api_sa: {
          project: metadata.projectId,
          account_id: 'vulncatcher-api-sa',
          display_name: 'Service Account for API Wrapper',
          depends_on: ['terraform_data.service_deps'],
        },
        job_sa: {
          project: metadata.projectId,
          account_id: 'vulncatcher-job-sa',
          display_name: 'Service Account for VulnCatcher CLI Job',
          depends_on: ['terraform_data.service_deps'],
        },
        invoker_sa: {
          project: metadata.projectId,
          account_id: 'vulncatcher-invoker-sa',
          display_name: 'Service Account for invoking IAP protected API',
          depends_on: ['terraform_data.service_deps'],
        },
      },
      google_cloud_run_v2_job: {
        cli_job: {
          deletion_protection: false,
          project: metadata.projectId,
          name: 'vulncatcher-cli-job',
          location: settings.region,
          depends_on: ['null_resource.build_image'],
          template: {
            template: {
              timeout: "%ss" % settings.scan_job_max_duration_seconds,
              max_retries: 0,
              service_account: '${google_service_account.job_sa.email}',
              containers: [{
                image: '%s-docker.pkg.dev/%s/${google_artifact_registry_repository.vulncatcher_repo.repository_id}/vulncatcher-container:latest' % [settings.region, metadata.projectId],
                command: ['bash', '/code/entrypoint.sh'],
                resources: {
                  limits: {
                    cpu: '2',
                    memory: '4Gi',
                  },
                },
              }],
            },
          },
        },
      },
      google_cloud_run_v2_service: {
        api_service: {
          deletion_protection: false,
          project: metadata.projectId,
          provider: 'google-beta',
          name: 'vulncatcher-api',
          ingress: 'INGRESS_TRAFFIC_ALL',
          iap_enabled: false,
          location: settings.region,
          template: {
            service_account: '${google_service_account.api_sa.email}',
            containers: [{
              image: 'scratch',
              command: ['npx'],
              args: ['@google-cloud/functions-framework', '--target=apiWrapper'],
              base_image_uri: '%s-docker.pkg.dev/serverless-runtimes/google-24-full/runtimes/nodejs24' % settings.region,
              env: [
                {
                  name: 'FUNCTION_TARGET',
                  value: 'apiWrapper',
                },
                {
                  name: 'PROJECT_ID',
                  value: metadata.projectId,
                },
                {
                  name: 'LOCATION',
                  value: settings.region,
                },
                {
                  name: 'JOB_NAME',
                  value: '${google_cloud_run_v2_job.cli_job.name}',
                },
                {
                  name: 'REPORTS_BUCKET',
                  value: '${google_storage_bucket.reports.name}',
                },
              ],
              resources: {
                limits: {
                  cpu: '2',
                  memory: '4Gi',
                },
              },
              source_code: {
                cloud_storage_source: {
                  bucket: '${google_storage_bucket.source.name}',
                  object: '${google_storage_bucket_object.source_tar.name}',
                  generation: '${google_storage_bucket_object.source_tar.generation}',
                },
              },
            }],
          },
        },
      },
      google_cloud_run_v2_job_iam_member: {
        job_developer: {
          name: '${google_cloud_run_v2_job.cli_job.name}',
          location: settings.region,
          role: 'roles/run.developer',
          member: 'serviceAccount:${google_service_account.api_sa.email}',
        },
      },
      google_project_iam_member: {
        api_sa_log_viewer: {
          project: metadata.projectId,
          role: 'roles/logging.viewer',
          member: 'serviceAccount:${google_service_account.api_sa.email}',
        },
        job_sa_vertex: {
          project: metadata.projectId,
          role: 'roles/aiplatform.user',
          member: 'serviceAccount:${google_service_account.job_sa.email}',
        },
      },
      google_storage_bucket_iam_member: {
        reports_writer: {
          bucket: '${google_storage_bucket.reports.name}',
          role: 'roles/storage.objectAdmin',
          member: 'serviceAccount:${google_service_account.job_sa.email}',
        },
      },
      google_cloud_run_v2_service_iam_member: {
        api_invoker: {
          project: metadata.projectId,
          location: settings.region,
          name: '${google_cloud_run_v2_service.api_service.name}',
          role: 'roles/run.invoker',
          member: 'serviceAccount:${google_service_account.api_sa.email}',
        },
      },
    },
    output: {
      api_url: {
        value: '${google_cloud_run_v2_service.api_service.uri}',
      },
    },
  },
  'services.tf.json': {
    data: {
      google_compute_default_service_account: {
        default: {
          project: metadata.projectId,
        },
      },
    },
    resource: {
      local builder_roles = [
        'cloudbuild.builds.editor',
        'serviceusage.serviceUsageConsumer',
        'storage.objectViewer',
        'artifactregistry.writer',
      ],

      google_project_iam_member: {
        ['build_sa_%s' % std.strReplace(role, '.', '_')]: {
          project: metadata.projectId,
          role: 'roles/%s' % role,
          member: 'serviceAccount:${data.google_compute_default_service_account.default.email}',
        }
        for role in builder_roles
      },
      google_project_service: {
        [std.split(service, '.')[0]]: {
          project: metadata.projectId,
          service: service,
        }
        for service in serviceList
      },
      terraform_data: {
        service_deps: {
          input: 'service-dependencies',
          depends_on: ['google_project_service.%s' % std.split(s, '.')[0] for s in serviceList],
        },
        builder_privilege_deps: {
          input: 'builder-privileges',
          depends_on: ['google_project_iam_member.build_sa_%s' % std.strReplace(role, '.', '_') for role in builder_roles],
        },
      },
    },
  },
  'scripts.tf.json': {
    locals: {
      cli_template_path: "${path.module}/../templates/vulncatcher_api.tpl",
      cli_template_vars: {
        API_URL: '${google_cloud_run_v2_service.api_service.uri}',
        REPORT_BUCKET: '${google_storage_bucket.reports.name}',
      },
      entrypoint_template_path: "${path.module}/../templates/entrypoint.tpl",
      entrypoint_template_vars: {
        REPORT_BUCKET: '${google_storage_bucket.reports.name}',
        REGION: settings.region,
      },

    },
    resource: {
      local_file: {
        cli_script: {
          content: "${templatefile(local.cli_template_path, local.cli_template_vars)}",
          filename: "${path.module}/../vulncatcher-api.sh",
          file_permission: "0700",
        },
        entrypoint_script: {
          content: "${templatefile(local.entrypoint_template_path, local.entrypoint_template_vars)}",
          filename: "${path.module}/../../entrypoint.sh",
          file_permission: "0700",
        },
      },
    },
  },
  'backend.tf.json': gcp.bootstrap('gs-shield-vulncatcher-api'),
  'providers.tf.json': {
    provider: gcp.providerAliases(settings.region, {
      project: metadata.projectId,
    }, false),
  },
  'providers-beta.tf.json': {
    provider: std.map(function(x) { 'google-beta': x.google }, gcp.providerAliases(settings.region, {
      project: metadata.projectId,
    }, false)),
  },
}
