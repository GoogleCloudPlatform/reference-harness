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

"""Unit tests for GCS uploading and CLI bucket verification."""

import os
from unittest.mock import MagicMock, patch

import pytest
from app.agent import _model, _model_fast
from app.cli.bootstrap import bootstrap_codebase_signatures
from app.cli.main import main
from app.cli.results import upload_to_gcs


def test_upload_to_gcs_success(tmp_path):
    local_file = tmp_path / "report.md"
    local_file.write_text("# Test Report")

    bucket_name = "test-bucket"
    dest_blob = "scans/report.md"

    mock_client_instance = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()

    mock_client_instance.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob

    with patch(
        "google.cloud.storage.Client", return_value=mock_client_instance
    ) as mock_client_cls:
        upload_to_gcs(str(local_file), bucket_name, dest_blob)

        mock_client_cls.assert_called_once()
        mock_client_instance.bucket.assert_called_once_with(bucket_name)
        mock_bucket.blob.assert_called_once_with(dest_blob)
        mock_blob.upload_from_filename.assert_called_once_with(str(local_file))


def test_upload_to_gcs_failure(tmp_path):
    local_file = tmp_path / "report.md"
    local_file.write_text("# Test Report")

    bucket_name = "test-bucket"
    dest_blob = "scans/report.md"

    mock_client_instance = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()

    mock_client_instance.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.upload_from_filename.side_effect = Exception("Upload Failed")

    with patch(
        "google.cloud.storage.Client", return_value=mock_client_instance
    ):
        with pytest.raises(Exception):
            upload_to_gcs(str(local_file), bucket_name, dest_blob)


def test_gemma_model_override():
    with patch.dict(
        os.environ,
        {
            "VULNCATCHER_GEMMA_ENDPOINT": "http://gemma-run.app",
            "VULNCATCHER_PRO_MODEL": "google/gemma-4-E4B-it",
            "VULNCATCHER_FLASH_MODEL": "google/gemma-4-E2B-it",
        },
    ):
        pro_llm = _model()
        flash_llm = _model_fast()

        assert pro_llm.__class__.__name__ == "StrippedLiteLlm"
        assert pro_llm.model == "openai/google/gemma-4-E4B-it"
        # pylint: disable=protected-access
        # Accessing protected member _additional_args to test client config
        assert pro_llm._additional_args["api_base"] == "http://gemma-run.app"

        assert flash_llm.__class__.__name__ == "StrippedLiteLlm"
        assert flash_llm.model == "openai/google/gemma-4-E2B-it"
        # pylint: disable=protected-access
        assert flash_llm._additional_args["api_base"] == "http://gemma-run.app"


def test_gemma_bootstrap_classification(tmp_path):
    # Create a dummy config to trigger bootstrapper logic
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text('{"name": "test"}')

    mock_resp = MagicMock()
    mock_resp.ok = True
    web_res = (
        '{"primary_category": "web", "web": {"patterns": [], '
        '"filenames": [], "extensions": [".js"]}}'
    )
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": web_res}}]
    }

    with patch.dict(
        os.environ, {"VULNCATCHER_GEMMA_ENDPOINT": "http://gemma-run.app"}
    ), patch("requests.post", return_value=mock_resp) as mock_post:

        boot_data = bootstrap_codebase_signatures(
            str(tmp_path), "google/gemma-4-E2B-it"
        )

        assert boot_data["category"] == "web"
        mock_post.assert_called_once()
        call_args = mock_post.call_args[0]
        assert call_args[0] == "http://gemma-run.app/v1/chat/completions"


def test_cli_bucket_verification_success():
    mock_args = MagicMock()
    mock_args.target_dir = "."
    mock_args.gcs_bucket = "valid-bucket"
    mock_args.gcs_prefix = ""
    mock_args.pro_model = None
    mock_args.flash_model = None
    mock_args.location = None
    mock_args.gemma_endpoint = None
    mock_args.scan_all = False
    mock_args.output_format = "markdown"
    mock_args.chunk_size = 25

    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_client.lookup_bucket.return_value = mock_bucket

    # Patch argparse to return mock_args, and other components to exit early
    with patch(
        "argparse.ArgumentParser.parse_args", return_value=mock_args
    ), patch("google.cloud.storage.Client", return_value=mock_client), patch(
        "app.cli.main.select_gcp_vertex_models", return_value=("pro", "flash")
    ), patch(
        "app.cli.main.bootstrap_codebase_signatures", return_value=None
    ), patch(
        "subprocess.run"
    ) as _, patch(
        "app.cli.main.map_boundaries", return_value={"boundary_files": []}
    ), patch(
        "app.cli.main.ADKServerManager"
    ) as mock_server_mgr:

        # Mock server manager to return port 18080
        mgr_inst = MagicMock()
        mgr_inst.start_adk_server.return_value = 18080
        mock_server_mgr.return_value = mgr_inst

        # We patch requests.post inside main to fail immediately so main exits
        with patch("requests.post", side_effect=RuntimeError("stop")):
            try:
                main()
            except RuntimeError as e:
                assert "stop" in str(e)

        mock_client.lookup_bucket.assert_called_once_with("valid-bucket")


def test_cli_bucket_verification_missing():
    mock_args = MagicMock()
    mock_args.target_dir = "."
    mock_args.gcs_bucket = "missing-bucket"

    mock_client = MagicMock()
    mock_client.lookup_bucket.return_value = None

    with patch(
        "argparse.ArgumentParser.parse_args", return_value=mock_args
    ), patch("google.cloud.storage.Client", return_value=mock_client):

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        mock_client.lookup_bucket.assert_called_once_with("missing-bucket")
