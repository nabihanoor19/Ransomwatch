# RansomWatch — Test Execution Results

**Date of Execution:** 2026-11-24  
**Environment:** Python 3.12.10, pytest 9.2.0, Windows x64  
**Total Tests:** 44  
**Passed:** 44 (100%)  
**Failed:** 0  

---

## Test Execution Summary

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0 -- D:\RansomWatch\backend\venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: D:\RansomWatch
plugins: anyio-4.16.0
collecting ... collected 44 items

tests/test_api.py::TestMonitorAPI::test_register_folder PASSED           [  2%]
tests/test_api.py::TestMonitorAPI::test_register_duplicate_folder_rejected PASSED [  4%]
tests/test_api.py::TestMonitorAPI::test_list_folders PASSED              [  6%]
tests/test_api.py::TestMonitorAPI::test_start_and_stop_monitoring PASSED [  9%]
tests/test_api.py::TestMonitorAPI::test_start_nonexistent_folder_returns_404 PASSED [ 11%]
tests/test_api.py::TestEventsAPI::test_create_event PASSED               [ 13%]
tests/test_api.py::TestEventsAPI::test_list_events PASSED                [ 15%]
tests/test_api.py::TestEventsAPI::test_list_events_filter_by_severity PASSED [ 18%]
tests/test_api.py::TestEventsAPI::test_get_single_event PASSED           [ 20%]
tests/test_api.py::TestEventsAPI::test_get_nonexistent_event_returns_404 PASSED [ 22%]
tests/test_api.py::TestIncidentsAPI::test_create_incident PASSED         [ 25%]
tests/test_api.py::TestIncidentsAPI::test_list_incidents PASSED          [ 27%]
tests/test_api.py::TestIncidentsAPI::test_get_incident_detail PASSED     [ 29%]
tests/test_api.py::TestIncidentsAPI::test_update_incident_status PASSED  [ 31%]
tests/test_api.py::TestIncidentsAPI::test_get_nonexistent_incident_returns_404 PASSED [ 34%]
tests/test_api.py::TestDashboardAPI::test_dashboard_stats PASSED         [ 36%]
tests/test_api.py::TestDashboardAPI::test_recent_events PASSED           [ 38%]
tests/test_api.py::TestDashboardAPI::test_severity_breakdown PASSED      [ 40%]
tests/test_api.py::TestDashboardAPI::test_dashboard_requires_auth PASSED [ 43%]
tests/test_api.py::TestAdminAPI::test_list_users PASSED                  [ 45%]
tests/test_api.py::TestAdminAPI::test_patch_user_role_and_status PASSED  [ 47%]
tests/test_api.py::TestAdminAPI::test_patch_configuration PASSED         [ 50%]
tests/test_api.py::TestAdminAPI::test_get_audit_logs PASSED              [ 52%]
tests/test_api.py::TestReportsAPI::test_export_json_report PASSED        [ 54%]
tests/test_api.py::TestReportsAPI::test_export_csv_report PASSED         [ 56%]
tests/test_api.py::TestReportsAPI::test_export_requires_auth PASSED      [ 59%]
tests/test_audit.py::test_redact_sensitive_data PASSED                   [ 61%]
tests/test_audit.py::test_login_success_and_failure_audit_logging PASSED [ 63%]
tests/test_audit.py::test_folder_and_monitoring_audit_logging PASSED     [ 65%]
tests/test_audit.py::test_file_event_and_incident_audit_logging PASSED   [ 68%]
tests/test_audit.py::test_report_and_config_audit_logging PASSED         [ 70%]
tests/test_audit.py::test_audit_logs_are_append_only PASSED              [ 72%]
tests/test_auth.py::test_scenario_1_correct_credentials_login_successful PASSED [ 75%]
tests/test_auth.py::test_scenario_2_wrong_password_returns_401 PASSED    [ 77%]
tests/test_auth.py::test_scenario_3_unknown_email_generic_failure PASSED [ 79%]
tests/test_auth.py::test_scenario_4_expired_token_access_denied PASSED   [ 81%]
tests/test_auth.py::test_scenario_5_missing_token_access_denied PASSED   [ 84%]
tests/test_auth.py::test_scenario_6_inactive_user_access_denied PASSED   [ 86%]
tests/test_auth.py::test_scenario_7_public_attempt_to_create_admin_rejected PASSED [ 88%]
tests/test_auth.py::test_scenario_8_logout_and_session_invalidation PASSED [ 90%]
tests/test_rbac.py::test_operator_endpoints_accessible_by_both_roles PASSED [ 93%]
tests/test_rbac.py::test_admin_endpoints_return_403_for_operators PASSED [ 95%]
tests/test_rbac.py::test_record_denied_administrative_access_attempt_in_audit_log PASSED [ 97%]
tests/test_rbac.py::test_admin_endpoints_accessible_by_admin PASSED      [100%]

====================== 44 passed in 13.03s ======================
```
