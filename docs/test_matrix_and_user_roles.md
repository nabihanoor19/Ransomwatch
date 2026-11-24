# RansomWatch — Comprehensive Test Matrix & User Roles Specification
## Quality Assurance, Security Verification & Viva Defense Document

This document provides a complete breakdown of all **44 automated test cases** implemented for the RansomWatch backend, categorized by user role, security domain, and API subsystem.

---

## 🎭 User Roles Definition

| Role | Description | Privilege Level | Permitted Operations |
|---|---|:---:|---|
| **Anonymous (Unauthenticated)** | External clients or unauthenticated requests | Public | Register new operator account, submit login credentials. All other operations receive `401 Unauthorized`. |
| **Operator** | Security analysts and operators monitoring file system activity | Standard Staff | View dashboard metrics, register folders, start/stop monitoring, view file events, create/view/update incidents, export audit & incident reports. |
| **Administrator** | System supervisors and security leads | Full Admin | All Operator privileges PLUS: manage user accounts (role assignment, account deactivation), view full security audit logs, modify detection thresholds and configuration rules. |

---

## 📊 Comprehensive 44-Test Case Matrix

### Suite 1: Authentication & Token Security (`tests/test_auth.py` — 8 Tests)

| # | Test Function | User Type | Endpoint & Method | Input Data | Expected Status | Security Assertion / Viva Defense |
|---|---|---|---|---|:---:|---|
| 1 | `test_scenario_1_correct_credentials_login_successful` | Anonymous | `POST /auth/register`<br>`POST /auth/login` | Valid credentials (`operator@example.com`, `Password123!`) | **201**, then **200** | Generates signed JWT (`HS256`, 30 min expiration). Password stored as Argon2id hash. |
| 2 | `test_scenario_2_wrong_password_returns_401` | Anonymous | `POST /auth/login` | Valid username, wrong password | **401** | Argon2 verify fails. Returns generic `"Incorrect username/email or password"`. Failed attempt logged. |
| 3 | `test_scenario_3_unknown_email_generic_failure` | Anonymous | `POST /auth/login` | Non-existent email (`does_not_exist@example.com`) | **401** | **User Enumeration Prevention**: Returns identical message as wrong password to prevent email harvesting. |
| 4 | `test_scenario_4_expired_token_access_denied` | Expired Token | `GET /auth/me` | JWT with `exp` in the past (-10 mins) | **401** | PyJWT catches `ExpiredSignatureError` and terminates request. |
| 5 | `test_scenario_5_missing_token_access_denied` | Anonymous | `GET /auth/me` | No `Authorization` header | **401** | FastAPI `OAuth2PasswordBearer` dependency blocks unauthenticated request. |
| 6 | `test_scenario_6_inactive_user_access_denied` | Inactive User | `POST /auth/login`<br>`GET /auth/me` | User with `is_active = False` in SQLite | **400** | **Immediate Revocation**: Database checked on each request; deactivated users cannot act even with valid JWT. |
| 7 | `test_scenario_7_public_attempt_to_create_admin_rejected` | Malicious Client | `POST /auth/register` | Body includes injected `"role": "admin"` | **201** | **Mass Assignment Prevention**: Schema ignores `role`, backend forces `role="operator"`. Access to admin route returns 403. |
| 8 | `test_scenario_8_logout_and_session_invalidation` | Operator | `POST /auth/logout` | Bearer token in header | **200** | Records `USER_LOGOUT` in `audit_logs` and instructs client to purge bearer token. |

---

### Suite 2: Role-Based Access Control (`tests/test_rbac.py` — 4 Tests)

| # | Test Function | User Type | Endpoint & Method | Input Data | Expected Status | Security Assertion / Viva Defense |
|---|---|---|---|---|:---:|---|
| 9 | `test_operator_endpoints_accessible_by_both_roles` | Operator & Admin | `GET /dashboard/stats` | Bearer token of Operator, then Admin | **200** | Both roles have access to operational monitoring. Anonymous access returns 401. |
| 10 | `test_admin_endpoints_return_403_for_operators` | Operator | `GET /admin/users`<br>`GET /admin/audit-logs`<br>`PATCH /admin/configurations/*` | Operator Bearer token | **403** | Server-side enforcement via `require_admin()` dependency. Returns `"Insufficient permissions"`. |
| 11 | `test_record_denied_administrative_access_attempt_in_audit_log` | Operator | `GET /admin/audit-logs` | Operator Bearer token | **403** | Violations are recorded in `audit_logs` with `action="ADMIN_ACCESS_DENIED"` and operator username. |
| 12 | `test_admin_endpoints_accessible_by_admin` | Admin | `GET /admin/users`<br>`PATCH /admin/configurations/*`<br>`GET /admin/audit-logs` | Admin Bearer token | **200** | Admin successfully executes elevated administrative tasks. |

---

### Suite 3: End-to-End API Subsystems (`tests/test_api.py` — 26 Tests)

#### Subsystem A: Folder Monitoring (`/monitor`)
| # | Test Function | User Type | Endpoint & Method | Input Data | Expected Status | Assertion / Description |
|---|---|---|---|---|:---:|---|
| 13 | `test_register_folder` | Operator | `POST /monitor/folders` | `{"folder_path": "D:/test/sandbox", "folder_name": "Sandbox"}` | **201** | Folder registered in SQLite with initial status `"stopped"`. |
| 14 | `test_register_duplicate_folder_rejected` | Operator | `POST /monitor/folders` | Identical folder path twice | **400** | Duplicate folder path rejected with 400 Bad Request. |
| 15 | `test_list_folders` | Operator | `GET /monitor/folders` | Valid token | **200** | Returns list of registered monitored folders. |
| 16 | `test_start_and_stop_monitoring` | Operator | `POST /monitor/start/{id}`<br>`POST /monitor/stop/{id}` | Existing folder ID | **200** | Status transitions: `stopped` → `active` → `stopped`. Logs created. |
| 17 | `test_start_nonexistent_folder_returns_404` | Operator | `POST /monitor/start/999999` | Non-existent folder ID | **404** | Returns 404 Not Found. |

#### Subsystem B: File Events (`/events`)
| # | Test Function | User Type | Endpoint & Method | Input Data | Expected Status | Assertion / Description |
|---|---|---|---|---|:---:|---|
| 18 | `test_create_event` | Operator / Module | `POST /events` | Event with severity `"HIGH"`, risk score `85.0`, evidence list | **201** | Assigns UUID `event_id`, stores event in SQLite. |
| 19 | `test_list_events` | Operator | `GET /events` | Valid token | **200** | Retrieves all recorded file events. |
| 20 | `test_list_events_filter_by_severity` | Operator | `GET /events?severity=HIGH` | Query parameter `severity=HIGH` | **200** | Returns only events matching HIGH severity. |
| 21 | `test_get_single_event` | Operator | `GET /events/{event_id}` | Event UUID | **200** | Retrieves exact event by UUID. |
| 22 | `test_get_nonexistent_event_returns_404` | Operator | `GET /events/{random_uuid}` | Invalid UUID | **404** | Returns 404 Not Found. |

#### Subsystem C: Incidents (`/incidents`)
| # | Test Function | User Type | Endpoint & Method | Input Data | Expected Status | Assertion / Description |
|---|---|---|---|---|:---:|---|
| 23 | `test_create_incident` | Operator | `POST /incidents` | Severity `"CRITICAL"`, risk score `95.0`, description | **201** | Assigns identifier `INC-XXXXXXXX`, initial status `"open"`. |
| 24 | `test_list_incidents` | Operator | `GET /incidents` | Valid token | **200** | Returns all incidents sorted newest first. |
| 25 | `test_get_incident_detail` | Operator | `GET /incidents/{incident_id}` | Incident ID (e.g. `INC-AB12CD34`) | **200** | Retrieves full incident object. |
| 26 | `test_update_incident_status` | Operator | `PATCH /incidents/{incident_id}` | `{"status": "investigating"}`, then `"resolved"` | **200** | Lifecycle transitions: `open` → `investigating` → `resolved`. |
| 27 | `test_get_nonexistent_incident_returns_404` | Operator | `GET /incidents/INC-ZZZZZZZZ` | Non-existent ID | **404** | Returns 404 Not Found. |

#### Subsystem D: Dashboard (`/dashboard`)
| # | Test Function | User Type | Endpoint & Method | Input Data | Expected Status | Assertion / Description |
|---|---|---|---|---|:---:|---|
| 28 | `test_dashboard_stats` | Operator | `GET /dashboard/stats` | Valid token | **200** | Returns aggregated counts (monitored folders, events, incidents by status). |
| 29 | `test_recent_events` | Operator | `GET /dashboard/recent-events` | Valid token | **200** | Returns top 10 most recent file events for activity feed. |
| 30 | `test_severity_breakdown` | Operator | `GET /dashboard/severity` | Valid token | **200** | Returns incident counts by severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| 31 | `test_dashboard_requires_auth` | Anonymous | `GET /dashboard/stats` | No token | **401** | Unauthenticated access rejected. |

#### Subsystem E: Administration (`/admin`)
| # | Test Function | User Type | Endpoint & Method | Input Data | Expected Status | Assertion / Description |
|---|---|---|---|---|:---:|---|
| 32 | `test_list_users` | Admin | `GET /admin/users` | Admin token | **200** | Retrieves all registered users with roles and active status. |
| 33 | `test_patch_user_role_and_status` | Admin | `PATCH /admin/users/{id}` | `{"is_active": false}` | **200** | Deactivates target account. Deactivation takes effect immediately. |
| 34 | `test_patch_configuration` | Admin | `PATCH /admin/configurations/entropy_threshold` | `{"value": 7.5, "is_enabled": true}` | **200** | Updates detection threshold rule. Creates rule if not present. |
| 35 | `test_get_audit_logs` | Admin | `GET /admin/audit-logs` | Admin token | **200** | Retrieves full security audit trail. |

#### Subsystem F: Reports (`/reports`)
| # | Test Function | User Type | Endpoint & Method | Input Data | Expected Status | Assertion / Description |
|---|---|---|---|---|:---:|---|
| 36 | `test_export_json_report` | Operator | `GET /reports/export?format=json` | Query parameter `format=json` | **200** | Returns structured JSON report with incident list and summary metrics. |
| 37 | `test_export_csv_report` | Operator | `GET /reports/export?format=csv` | Query parameter `format=csv` | **200** | Generates and streams downloadable CSV file (`text/csv` attachment). |
| 38 | `test_export_requires_auth` | Anonymous | `GET /reports/export` | No token | **401** | Unauthenticated export attempt blocked. |

---

### Suite 4: Audit Logging, Redaction & Append-Only Security (`tests/test_audit.py` — 6 Tests)

| # | Test Function | User Type | Subsystem / Operation | Input Data | Expected Status | Security Assertion / Viva Defense |
|---|---|---|---|---|:---:|---|
| 39 | `test_redact_sensitive_data` | Unit / Internal | `AuditService.redact_sensitive_data()` | Dict with passwords, tokens, API keys, secrets | **N/A** | **Secret Scrubbing**: Recursively scrubs all sensitive keys to `"[REDACTED]"`. |
| 40 | `test_login_success_and_failure_audit_logging` | Anonymous | `POST /auth/login` | Valid credentials, then invalid credentials | **200**, then **401** | Records `USER_LOGIN` and `USER_LOGIN_FAILED`. Passwords are NOT stored in details. |
| 41 | `test_folder_and_monitoring_audit_logging` | Operator | `POST /monitor/*` | Register, start, stop folder monitoring | **201**, **200** | Records `FOLDER_REGISTERED`, `MONITORING_STARTED`, `MONITORING_STOPPED`. |
| 42 | `test_file_event_and_incident_audit_logging` | Operator | `POST /events`<br>`POST /incidents` | Submit event, create incident, update status | **201**, **200** | Records `FILE_EVENT_RECEIVED`, `INCIDENT_CREATED`, `INCIDENT_STATUS_UPDATED`. |
| 43 | `test_report_and_config_audit_logging` | Operator & Admin | `GET /reports/export`<br>`PATCH /admin/configurations/*` | Export report, update detection threshold | **200** | Records `REPORT_EXPORTED` and `ADMIN_CONFIGURATION_CHANGED`. |
| 44 | `test_audit_logs_are_append_only` | Admin | `DELETE /admin/audit-logs`<br>`PATCH /admin/audit-logs` | Modification / deletion requests | **405** | **Append-Only Enforcement**: The API exposes no route to delete or alter past audit logs. |

---

## 🎯 Viva Defense & Examiner Q&A Guide

### Q1: Why did you choose Argon2id instead of bcrypt or standard SHA-256?
- **Answer**: SHA-256 is designed for fast checksum calculation and has zero memory requirements, meaning modern graphics cards (GPUs) and ASICs can compute billions of SHA-256 hashes per second to brute-force passwords.
- Bcrypt is better, but it truncates passwords at 72 bytes and is vulnerable to GPU acceleration.
- **Argon2id** won the Password Hashing Competition (PHC). It is memory-hard (requires RAM to compute) and compute-hard, making GPU and ASIC parallel cracking attacks economically and computationally infeasible.

### Q2: If JWTs are stateless, why do you query SQLite on every request in `get_current_user`?
- **Answer**: A purely stateless token has a dangerous vulnerability: if an operator's account is deactivated or compromised, their token remains fully valid until the 30-minute expiration passes.
- By verifying `is_active` against SQLite in `get_current_active_user`, account deactivation or role revocation takes effect **instantly on the very next HTTP request**.

### Q3: How do you prevent Privilege Escalation during public registration?
- **Answer**: We use schema isolation. The `UserCreate` Pydantic model accepted by `POST /auth/register` does not contain a `role` field. Even if an attacker passes `"role": "admin"` in their JSON payload, the backend ignores it and explicitly sets `role="operator"`. Administrator accounts can only be provisioned by existing administrators via `/admin/users`.

### Q4: How is the Audit Log protected against tampering?
- **Answer**:
  1. **No Mutation Endpoints**: There are no `DELETE`, `PUT`, or `PATCH` endpoints for `/admin/audit-logs` (returning `405 Method Not Allowed`).
  2. **Secret Redaction**: All details are scrubbed so that passwords and access tokens never enter the database.
  3. **Mirror Logging**: If a database error occurs, the event is immediately written to a secondary stream logger so security evidence is never lost.
