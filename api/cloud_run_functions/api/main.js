// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const {JobsClient, ExecutionsClient} = require('@google-cloud/run').v2;
const {Logging} = require('@google-cloud/logging');
const express = require('express');

const app = express();
app.use(express.json());

const jobsClient = new JobsClient();
const executionsClient = new ExecutionsClient();

const projectId = process.env.PROJECT_ID;
const location = process.env.LOCATION;
const jobName = process.env.JOB_NAME;
const reportsBucket = process.env.REPORTS_BUCKET;

const logging = new Logging({projectId});

// POST /run: Invokes the Cloud Run Job
app.post('/run', async (req, res) => {
  const {proModel, flashModel, repo, ref} = req.body;
  if (!proModel || !flashModel || !repo || !ref) {
    return res.status(400).send({
      error:
        'Missing "proModel", "flashModel", ' +
        '"repo", or "ref" parameter in request body.',
    });
  }

  try {
    // Initiate the job without awaiting the long-running operation's resolution
    const [operation] = await jobsClient.runJob({
      name: `projects/${projectId}/locations/${location}/jobs/${jobName}`,
      overrides: {
        containerOverrides: [
          {
            args: [
              '--pro-model', proModel,
              '--flash-model', flashModel,
              '--repo', repo,
              '--ref', ref,
            ],
          },
        ],
      },
    });

    if (!operation || !operation.metadata || !operation.metadata.name) {
      throw new Error(
          'Failed to retrieve execution details from job run operation.',
      );
    }

    const executionName = operation.metadata.name;
    const executionId = executionName.split('/').pop();

    // Return immediately to the client
    res.status(202).send({
      message: 'Job execution initiated.',
      executionId: executionId,
      gcsBucketPrefix: `gs://${reportsBucket}/${executionId}/`,
    });
  } catch (error) {
    res.status(500).send({error: error.message});
  }
});

// POST /terminate: Aborts an active execution
app.post('/terminate', async (req, res) => {
  const {executionId} = req.body;
  if (!executionId) {
    return res.status(400).send({error: 'Missing "executionId" parameter.'});
  }

  try {
    const [operation] = await executionsClient.cancelExecution({
      name:
        `projects/${projectId}/locations/${location}` +
        `/jobs/${jobName}/executions/${executionId}`,
    });

    // Wait for the cancellation to be acknowledged
    await operation.promise();

    res.status(200).send({
      message: `Execution ${executionId} has been terminated.`,
    });
  } catch (error) {
    res.status(500).send({error: error.message});
  }
});

// GET /status/:executionId: Queries current execution status and returns the
// most recent 20 logs
app.get('/status/:executionId', async (req, res) => {
  const {executionId} = req.params;
  if (!executionId) {
    return res.status(400).send({error: 'Missing "executionId" parameter.'});
  }

  try {
    const [execution] = await executionsClient.getExecution({
      name:
        `projects/${projectId}/locations/${location}` +
        `/jobs/${jobName}/executions/${executionId}`,
    });

    const filter =
      'resource.type="cloud_run_job" AND ' +
      `resource.labels.job_name="${jobName}" AND ` +
      `resource.labels.location="${location}" AND ` +
      `labels."run.googleapis.com/execution_name"="${executionId}"`;

    const [entries] = await logging.getEntries({
      filter: filter,
      pageSize: 20,
      orderBy: 'timestamp desc',
    });

    const logs = entries.map((entry) => ({
      timestamp: entry.metadata.timestamp,
      severity: entry.metadata.severity,
      message: entry.data,
    })).reverse().map((e) => e.message).slice(-20);

    res.status(200).send({
      executionId,
      conditions: execution.conditions.map((e) => {
        return `${e.type}: ${e.message}`;
      }),
      logs,
    });
  } catch (error) {
    res.status(500).send({error: error.message});
  }
});

exports.apiWrapper = app;
