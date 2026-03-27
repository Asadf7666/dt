from __future__ import annotations

import json

import requests

from TIPCommon.base.action import Action
from TIPCommon.extraction import extract_action_param, extract_configuration_param
from TIPCommon import validation
from TIPCommon.utils import is_empty_string_or_none
from TIPCommon.types import SingleJson

import consts
from exceptions import GoogleChroniclValidationError, GoogleChroniclManagerError
from GoogleChroniclManagerV2 import GoogleChroniclManagerV2
from utils import validate_api_root_for_backstory

# ─────────────────────────────────────────────────────────────────────────────
# Crowdstrike_Whitelist1 columns:
#   ParentCommandLine | CommandLine | user | BFC | detection_title
#   Added_by | Jira | removed  (+ any hidden columns)
#
# Example Row Filter:         {"Jira": "SIEMCLD-0069"}
# Example Column Values:      {"removed": "YES"}
# Multi-column update:        {"removed": "YES", "Added_by": "John.Doe"}
# ─────────────────────────────────────────────────────────────────────────────


class PatchRowInDataTable(Action):

    def __init__(self) -> None:
        super().__init__(consts.PATCH_ROW_IN_DATA_TABLE_SCRIPT_NAME)
        self.error_output_message = f"Error executing action \"{self.name}\"."
        self.output_message = ""
        self.result_value = False
        self.json_results: list[SingleJson] = []

    # ── Parameter extraction ──────────────────────────────────────────────────

    def _extract_action_parameters(self) -> None:
        self.params.user_service_account = extract_configuration_param(
            self.soar_action,
            provider_name=consts.INTEGRATION_NAME,
            param_name="User's Service Account",
            remove_whitespaces=False,
        )
        self.params.workload_identity_email = extract_configuration_param(
            self.soar_action,
            provider_name=consts.INTEGRATION_NAME,
            param_name="Workload Identity Email",
        )
        self.params.api_root = extract_configuration_param(
            self.soar_action,
            provider_name=consts.INTEGRATION_NAME,
            param_name="API Root",
            is_mandatory=True,
            print_value=True,
        )
        self.params.verify_ssl = extract_configuration_param(
            self.soar_action,
            provider_name=consts.INTEGRATION_NAME,
            param_name="Verify SSL",
            is_mandatory=True,
            input_type=bool,
            print_value=True,
        )
        # e.g. "Crowdstrike_Whitelist1"
        self.params.data_table_name = extract_action_param(
            self.soar_action,
            param_name="Data Table Name",
            print_value=True,
            is_mandatory=True,
        )
        # JSON object identifying the row to patch.
        # e.g. {"Jira": "SIEMCLD-0069"}
        self.params.row_filter = extract_action_param(
            self.soar_action,
            param_name="Row Filter",
            print_value=True,
            is_mandatory=True,
        )
        # JSON object with column(s) to update and their new values.
        # e.g. {"removed": "YES"}
        # e.g. {"removed": "YES", "Added_by": "John.Doe"}
        self.params.column_values_to_update = extract_action_param(
            self.soar_action,
            param_name="Column Values to Update",
            print_value=True,
            is_mandatory=True,
        )
        self.params.row_filter_parsed: SingleJson = {}
        self.params.updates_parsed: SingleJson = {}

    # ── Validation ────────────────────────────────────────────────────────────

    def _validate_params(self) -> None:
        validate_api_root_for_backstory(self.params.api_root)
        validator = validation.ParameterValidator(self.soar_action)
        if not is_empty_string_or_none(self.params.user_service_account):
            self.params.user_service_account = validator.validate_json(
                param_name="User's Service Account",
                json_string=self.params.user_service_account,
                print_value=False,
            )
        self._parse_and_validate_filter_param()
        self._parse_and_validate_updates_param()

    def _parse_and_validate_filter_param(self) -> None:
        try:
            parsed = json.loads(self.params.row_filter)
            if not isinstance(parsed, dict):
                raise ValueError("Parameter 'Row Filter' must be a JSON object.")
            if not parsed:
                raise ValueError("Parameter 'Row Filter' must not be empty.")
            self.params.row_filter_parsed = parsed
        except json.JSONDecodeError as e:
            raise GoogleChroniclValidationError(
                "Invalid value in \"Row Filter\". "
                "Example: {\"Jira\": \"SIEMCLD-0069\"}"
            ) from e
        except ValueError as e:
            raise GoogleChroniclValidationError(str(e)) from e

    def _parse_and_validate_updates_param(self) -> None:
        try:
            parsed = json.loads(self.params.column_values_to_update)
            if not isinstance(parsed, dict):
                raise ValueError(
                    "Parameter 'Column Values to Update' must be a JSON object."
                )
            if not parsed:
                raise ValueError(
                    "Parameter 'Column Values to Update' must not be empty."
                )
            self.params.updates_parsed = parsed
        except json.JSONDecodeError as e:
            raise GoogleChroniclValidationError(
                "Invalid value in \"Column Values to Update\". "
                "Example: {\"removed\": \"YES\"}"
            ) from e
        except ValueError as e:
            raise GoogleChroniclValidationError(str(e)) from e

    # ── API client ────────────────────────────────────────────────────────────

    def _init_api_clients(self) -> GoogleChroniclManagerV2:
        return GoogleChroniclManagerV2.create_manager_instance(
            user_service_account=self.params.user_service_account,
            chronicle_soar=self.soar_action,
            api_root=self.params.api_root,
            verify_ssl=self.params.verify_ssl,
            workload_identity_email=self.params.workload_identity_email,
        )

    # ── Main flow ─────────────────────────────────────────────────────────────

    def perform_action(self, _=None) -> None:
        ordered_column_names = self._fetch_and_validate_table_schema()
        self._validate_columns_against_schema(ordered_column_names)
        matching_row = self._find_row_to_patch(ordered_column_names)
        patched_row = self._call_patch_api(matching_row, ordered_column_names)
        self._process_api_response(patched_row)

    # ── Schema helpers ────────────────────────────────────────────────────────

    def _fetch_and_validate_table_schema(self) -> list[str]:
        table_details = self.api_client.data_table_details(
            self.params.data_table_name
        )
        if not table_details.column_info:
            raise GoogleChroniclValidationError(
                f"Data table '{self.params.data_table_name}' has no column info."
            )
        ordered_column_names = table_details.ordered_column_names
        if not ordered_column_names:
            raise GoogleChroniclValidationError(
                f"Data table '{self.params.data_table_name}' has no valid columns defined."
            )
        self.soar_action.LOGGER.info(
            f"Table schema fetched. Columns: {ordered_column_names}"
        )
        return ordered_column_names

    def _validate_columns_against_schema(
        self,
        ordered_column_names: list[str],
    ) -> None:
        valid_columns = {col.lower() for col in ordered_column_names}

        for key in self.params.row_filter_parsed:
            if key.lower() not in valid_columns:
                raise GoogleChroniclValidationError(
                    f"Column '{key}' in \"Row Filter\" does not exist in "
                    f"'{self.params.data_table_name}'. "
                    f"Valid columns: {list(ordered_column_names)}"
                )

        for key in self.params.updates_parsed:
            if key.lower() not in valid_columns:
                raise GoogleChroniclValidationError(
                    f"Column '{key}' in \"Column Values to Update\" does not exist in "
                    f"'{self.params.data_table_name}'. "
                    f"Valid columns: {list(ordered_column_names)}"
                )

        self.soar_action.LOGGER.info("All input columns passed schema validation.")

    # ── Row finder ────────────────────────────────────────────────────────────

    def _find_row_to_patch(self, ordered_column_names: list[str]) -> SingleJson:
        column_index_map = {
            col.lower(): idx for idx, col in enumerate(ordered_column_names)
        }
        normalized_filter = {
            c.lower(): str(v).strip().lower()
            for c, v in self.params.row_filter_parsed.items()
        }

        filter_val = next(iter(normalized_filter.items()))
        self.soar_action.LOGGER.info(
            f"Searching rows with server-side filter: '{filter_val}'"
        )

        for row in self.api_client.list_all_data_table_rows(
            data_table_identifier=self.params.data_table_name,
            filter_query=filter_val,
        ):
            is_match = True
            for col, expected_val in normalized_filter.items():
                idx = column_index_map.get(col)
                if idx is None or idx >= len(row.values):
                    is_match = False
                    break
                actual_val = str(row.values[idx]).strip().lower()
                if actual_val != expected_val:
                    is_match = False
                    break

            if is_match:
                self.soar_action.LOGGER.info(
                    f"Found matching row to patch: {row.name}"
                )
                return row

        raise GoogleChroniclValidationError(
            f"No row matching filter {self.params.row_filter_parsed} "
            f"was found in data table '{self.params.data_table_name}'."
        )

    # ── Direct PATCH REST call (no manager method needed) ─────────────────────

    def _call_patch_api(
        self,
        row: SingleJson,
        ordered_column_names: list[str],
    ) -> dict:
        """
        Calls the Chronicle PATCH endpoint directly:
            PATCH /v1alpha/{row.name}?updateMask=values

        Confirmed from official docs:
            https://chronicle.{region}.rep.googleapis.com/v1alpha/{dataTableRow.name}
        Only the 'values' field is supported by updateMask (per API docs).

        Uses the authenticated session already held by api_client.
        No changes to GoogleChroniclManagerV2 are needed.
        """
        row_id = row.name.split("/")[-1]
        column_index_map = {
            col.lower(): idx for idx, col in enumerate(ordered_column_names)
        }

        # Copy all current values, then overwrite only the changed columns
        updated_values = list(row.values)
        for col, new_val in self.params.updates_parsed.items():
            idx = column_index_map.get(col.lower())
            if idx is not None:
                self.soar_action.LOGGER.info(
                    f"  Column '{col}' (index {idx}): "
                    f"'{row.values[idx]}' -> '{new_val}'"
                )
                updated_values[idx] = str(new_val)

        # api_root is extracted directly from the integration config param and passed
        # to the manager — it already contains the correct regional base URL.
        # row.name is the full resource path returned by list_all_data_table_rows, e.g.:
        # projects/{p}/locations/{l}/instances/{i}/dataTables/{table}/dataTableRows/{rowId}
        url = f"{self.params.api_root.rstrip('/')}/v1alpha/{row.name}"
        payload = {
            "name": row.name,
            "values": updated_values,
        }

        self.soar_action.LOGGER.info(
            f"PATCH {url}  |  updated columns: {list(self.params.updates_parsed.keys())}"
        )

        # Grab the auth session that the Chronicle manager already set up.
        # Try the most common attribute names used across Chronicle manager versions.
        http_session = (
            getattr(self.api_client, "session", None)
            or getattr(self.api_client, "_session", None)
            or getattr(self.api_client, "http_client", None)
        )

        if http_session is None:
            raise GoogleChroniclValidationError(
                "Could not find the HTTP session on GoogleChroniclManagerV2. "
                "Open the manager file, find the session attribute in __init__, "
                "and add its name to the getattr() calls in _call_patch_api."
            )

        try:
            response = http_session.patch(
                url,
                json=payload,
                params={"updateMask": "values"},
                verify=self.params.verify_ssl,
            )
            response.raise_for_status()
        except requests.HTTPError as e:
            raise GoogleChroniclManagerError(
                f"HTTP {e.response.status_code} patching row '{row_id}': "
                f"{e.response.text}"
            ) from e
        except requests.RequestException as e:
            raise GoogleChroniclManagerError(
                f"Network error patching row '{row_id}': {e}"
            ) from e

        return response.json()

    # ── Response processing ───────────────────────────────────────────────────

    def _process_api_response(self, patched_row: dict | None) -> None:
        if patched_row:
            self.result_value = True
            self.output_message = (
                f"Successfully patched row in data table "
                f"\"{self.params.data_table_name}\" in Google SecOps."
            )
            self.json_results = [patched_row]
        else:
            self.result_value = False
            self.output_message = (
                f"Failed to patch the row in data table "
                f"\"{self.params.data_table_name}\". "
                "The API returned no data."
            )


def main() -> None:
    PatchRowInDataTable().run()


if __name__ == "__main__":
    main()
