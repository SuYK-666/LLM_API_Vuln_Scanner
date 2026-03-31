# LLM API Broken Access Control Report

- Endpoints Tested: 8
- Findings: 8
- Overall Risk: High
- High/Medium/Low: High=3, Medium=2, Low=1

## Findings
### Finding 1

#### Risk Object
- API: GET http://127.0.0.1:8000/api/v1/order/detail?order_id=50001

#### Trigger Condition
- Used an attack payload named order-id-increment, test rationale: Horizontal escalation via sequential ID enumeration.; specific override parameters: query={'order_id': '50002'}
- Trigger Payload: order-id-increment

#### Risk Evidence (Key)
- Status Compare: baseline=200 / attack=200
- Similarity: 0.94
- Sensitive Hits: {'phone': 1}
- JSON Schema Overlap:
  - shared_keys=7
  - baseline_keys=7
  - attack_keys=7
  - overlap_ratio=1.00
- Evidence Highlight: Detected successful unauthorized request returning 200, and unauthorized phone number records were matched via regular expression; sensitive field type: phone; hit count: phone=1.
- Reasons:
  - Baseline and attack both returned 200.
  - High body similarity detected (0.94).
  - JSON key structure is highly consistent between baseline and attack (shared=7/7, overlap=1.00).
  - Sensitive data patterns matched: {'phone': 1}.
- Baseline Preview:
  - {"code":0,"data":{"amount":199.0,"order_id":"50001","phone":"13800138001","uid":"1001"},"msg":"ok"} 
- Attack Preview:
  - {"code":0,"data":{"amount":499.0,"order_id":"50002","phone":"13900139002","uid":"1002"},"msg":"ok"} 

#### Impact Analysis
- Attackers can enumerate parameters to obtain high-value sensitive private data such as phone numbers of other users within the system without authorization, potentially leading to large-scale data breaches.

#### Conclusion
- Comprehensive risk assessment level: High. Vulnerability exploitation successful, clear privilege escalation behavior exists.

### Mitigation & Prevention
- Summary: Horizontal privilege escalation via sequential order ID enumeration allows unauthorized access to other users' order details. The API endpoint lacks server-side ownership validation, returning sensitive data (phone numbers) for orders belonging to different users.
- Immediate Fixes:
  - Add server-side ownership check: verify authenticated user ID matches order's user ID before returning data
  - Implement deny-by-default authorization: reject all requests unless explicit ownership/RBAC validation passes
  - Replace numeric order IDs with cryptographically random UUIDs to reduce enumerability
  - Add authorization middleware that validates user ownership for every /order/detail request
- Engineering Hardening:
  - Implement centralized authorization service/middleware with RBAC/ABAC policies for all sensitive endpoints
  - Design API to accept resource identifiers via path parameters (e.g., /orders/{order_id}) with built-in ownership validation
  - Use signed tokens (JWT) with embedded user ID and enforce server-side session validation
  - Create reusable authorization utilities for common patterns (ownership checks, role checks, permission checks)
  - Implement resource-based access control where each resource stores owner ID and access policies
- Detection and Monitoring:
  - Add audit logging for all order access attempts including: user ID, requested order ID, ownership validation result
  - Implement real-time alerts for failed ownership checks or suspicious access patterns (rapid ID enumeration)
  - Create security unit tests that verify authorization failures when users attempt to access others' orders
  - Monitor API logs for horizontal escalation patterns: sequential ID access across different user accounts
  - Implement integration tests simulating authenticated users trying to access unauthorized resources
- Suggestion Source: llm_mitigation_pass

### Finding 2

#### Risk Object
- API: GET http://127.0.0.1:8000/api/v1/user/profile?uid=1001

#### Trigger Condition
- Used an attack payload named uid-increment. Test rationale: Horizontal escalation: numeric ID increment to access another user's profile. Specific override parameter: query={'uid': '1002'}
- Trigger Payload: uid-increment

#### Risk Evidence (Key)
- Status Compare: baseline=200 / attack=200
- Similarity: 0.8278
- Sensitive Hits: {'phone': 1, 'email': 1, 'id_card': 1}
- JSON Schema Overlap:
  - shared_keys=9
  - baseline_keys=9
  - attack_keys=9
  - overlap_ratio=1.00
- Evidence Highlight: Detected successful unauthorized request returning 200, and unauthorized phone number records were matched via regex; sensitive field types: phone, email, id_card; hit statistics: phone=1, email=1, id_card=1.
- Reasons:
  - Baseline and attack both returned 200.
  - Moderate body similarity detected (0.83).
  - JSON key structure is highly consistent between baseline and attack (shared=9/9, overlap=1.00).
  - Sensitive data patterns matched: {'phone': 1, 'email': 1, 'id_card': 1}.
- Baseline Preview:
  - {"code":0,"data":{"address":"Shanghai Pudong District","email":"zhangsan@example.com","id_card":"110101199001011234","name":"Zhang San","phone":"13800138001","uid":"1001"},"msg":"ok"} 
- Attack Preview:
  - {"code":0,"data":{"address":"Beijing Haidian District","email":"lisi@example.com","id_card":"110101199202023456","name":"Li Si","phone":"13900139002","uid":"1002"},"msg":"ok"} 

#### Impact Analysis
- Attackers can enumerate parameters to obtain high-value sensitive private data of other users within the system, such as phone, email, and id_card, without authorization, potentially leading to large-scale data breaches.

#### Conclusion
- Comprehensive risk level assessment: High. Vulnerability exploitation successful, with clear evidence of privilege escalation.

### Mitigation & Prevention
- Summary: Horizontal privilege escalation via predictable numeric user ID parameter allows unauthorized access to other users' sensitive profile data (phone, email, ID card).
- Immediate Fixes:
  - Add server-side ownership validation: verify authenticated user ID from JWT/session matches requested uid parameter before returning data.
  - Replace sequential numeric IDs with random UUIDs for user identifiers in API parameters.
  - Implement deny-by-default authorization: reject all requests unless explicit ownership or role-based permission is verified.
  - Add audit logging for all profile access attempts, flagging mismatches between authenticated user and requested uid.
- Engineering Hardening:
  - Implement centralized authorization middleware that validates resource ownership for every sensitive endpoint.
  - Adopt Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) with explicit permission definitions.
  - Use indirect reference maps: map session/user tokens to internal IDs instead of exposing direct object identifiers.
  - Design API to use path parameters like /api/v1/user/profile (auto-derived from auth token) instead of query parameters with mutable IDs.
  - Create security unit tests that verify authorization failures when users attempt to access resources they don't own.
- Detection and Monitoring:
  - Implement real-time monitoring for IDOR patterns: alert on sequential ID access patterns or rapid uid parameter changes.
  - Log all sensitive data access with user context, requested resource ID, and authorization decision for audit trails.
  - Deploy anomaly detection to identify cross-account access attempts (e.g., user accessing multiple unrelated profiles).
  - Conduct regular automated security scans testing for broken access control using both authenticated and unauthenticated probes.
  - Establish security regression tests that verify fixed vulnerabilities remain patched across code changes.
- Suggestion Source: llm_mitigation_pass

### Finding 3

#### Risk Object
- API: GET http://127.0.0.1:8000/api/v1/admin/audit

#### Trigger Condition
- Used an attack payload named admin-role-header, test rationale: Replace user token with admin token for vertical escalation; specific override parameters: headers={'Authorization': 'Bearer admin_token'}
- Trigger Payload: admin-role-header

#### Risk Evidence (Key)
- Status Compare: baseline=200 / attack=200
- Similarity: 1.0
- Sensitive Hits: {'phone': 1, 'email': 1}
- JSON Schema Overlap:
  - shared_keys=7
  - baseline_keys=7
  - attack_keys=7
  - overlap_ratio=1.00
- Evidence Highlight: Detected successful unauthorized request returning 200, and unauthorized phone number records were matched via regex; sensitive field types: phone, email; hit statistics: phone=1, email=1.
- Reasons:
  - Baseline and attack both returned 200.
  - High body similarity detected (1.00).
  - JSON key structure is highly consistent between baseline and attack (shared=7/7, overlap=1.00).
  - Sensitive data patterns matched: {'phone': 1, 'email': 1}.
- Baseline Preview:
  - {"code":0,"data":{"ops_email":"ops_team@example.com","ops_phone":"13600136000","service":"payment","ticket_id":"AUD-2026-0042"},"msg":"ok"} 
- Attack Preview:
  - {"code":0,"data":{"ops_email":"ops_team@example.com","ops_phone":"13600136000","service":"payment","ticket_id":"AUD-2026-0042"},"msg":"ok"} 

#### Impact Analysis
- Attackers can enumerate parameters to obtain high-value sensitive private data such as phone numbers and emails of other users within the system without authorization, potentially leading to large-scale data breaches.

#### Conclusion
- Comprehensive risk assessment level: High. Vulnerability exploitation successful, clear evidence of unauthorized access behavior.

### Mitigation & Prevention
- Summary: Vertical privilege escalation via admin token substitution on admin audit endpoint, allowing unauthorized access to sensitive audit data.
- Immediate Fixes:
  - Implement server-side authorization middleware that validates user role from verified JWT claims, not just token presence
  - Add explicit role-based access control (RBAC) check for admin endpoints before processing requests
  - Replace static admin token validation with dynamic role verification from authenticated user session
  - Apply deny-by-default policy to all admin endpoints requiring explicit admin role verification
- Engineering Hardening:
  - Implement ABAC (Attribute-Based Access Control) with centralized authorization service for all sensitive endpoints
  - Use opaque, non-enumerable identifiers (UUIDs) for all resource references to prevent ID enumeration attacks
  - Add mandatory ownership checks for every resource access, even for admin roles with appropriate scoping
  - Create security unit tests validating authorization failures when non-admin tokens access admin endpoints
  - Implement comprehensive integration tests for RBAC/ABAC rules across all API endpoints
- Detection and Monitoring:
  - Enable detailed audit logging for all admin endpoint access attempts including user ID, role, and outcome
  - Implement real-time alerting for privilege escalation attempts and unauthorized admin access
  - Create anomaly detection for cross-account access patterns and unusual role usage
  - Establish regular security review of authorization logs for broken access control patterns
  - Monitor and alert on failed authorization attempts with subsequent successful access using different tokens
- Suggestion Source: llm_mitigation_pass

### Finding 4

#### Risk Object
- API: GET http://127.0.0.1:8000/api/v1/user/settings?uid=1001

#### Trigger Condition
- Used an attack payload named uid-increment. Test rationale: Horizontal escalation: numeric ID increment to access another user's settings. Specific override parameters: query={'uid': '1002'}
- Trigger Payload: uid-increment

#### Risk Evidence (Key)
- Status Compare: baseline=200 / attack=200
- Similarity: 0.9512
- Sensitive Hits: {}
- JSON Schema Overlap:
  - shared_keys=9
  - baseline_keys=10
  - attack_keys=10
  - overlap_ratio=0.90
- Evidence Highlight: No sensitive patterns such as phone numbers/email addresses/ID cards were matched.
- Reasons:
  - Baseline and attack both returned 200.
  - High body similarity detected (0.95).
  - JSON key structure is highly consistent between baseline and attack (shared=9/10, overlap=0.90).
  - Score capped at 70 because no sensitive data pattern was matched.
- Baseline Preview:
  - {"code":0,"data":{"nickname":"zs_dev","notification":{"email":true,"sms":false},"theme":"light","trace_1774937729822_894":"request-bound","uid":"1001"},"msg":"ok"} 
- Attack Preview:
  - {"code":0,"data":{"nickname":"zs_dev","notification":{"email":true,"sms":false},"theme":"light","trace_1774937856700_330":"request-bound","uid":"1001"},"msg":"ok"} 

#### Impact Analysis
- Attackers can perform sensitive operations or view unauthorized pages beyond their privileges.

#### Conclusion
- Comprehensive risk assessment level: Medium. Vulnerability exploitation successful, clear evidence of privilege escalation behavior.

### Mitigation & Prevention
- Summary: Horizontal privilege escalation via predictable numeric user ID parameter allows unauthorized access to other users' settings. The endpoint returns sensitive user data without verifying the authenticated user owns the requested resource.
- Immediate Fixes:
  - Add server-side ownership validation: compare authenticated user ID from session/token with requested uid parameter before processing.
  - Implement deny-by-default authorization: reject all requests where authenticated user doesn't match resource owner unless explicitly allowed.
  - Replace numeric ID parameter with session-derived user identifier where possible to prevent parameter manipulation.
- Engineering Hardening:
  - Implement centralized authorization middleware that validates resource ownership for all sensitive endpoints.
  - Use opaque identifiers (UUIDs) instead of sequential numeric IDs to reduce predictability of IDOR attacks.
  - Enforce Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) for all API endpoints.
  - Add security unit/integration tests that verify authorization failures when users attempt to access others' resources.
  - Implement parameter binding validation that rejects requests where user attempts to specify another user's identifier.
- Detection and Monitoring:
  - Add audit logging for all user settings access attempts, including requested UID and authenticated UID.
  - Implement real-time alerting for cross-account access attempts (where requested UID ≠ authenticated UID).
  - Create security monitoring dashboards tracking authorization failure rates and suspicious parameter patterns.
  - Regularly review access logs for horizontal privilege escalation patterns using automated analysis.
  - Implement canary tokens or honeypot user accounts to detect enumeration and unauthorized access attempts.
- Suggestion Source: llm_mitigation_pass

### Finding 5

#### Risk Object
- API: GET http://127.0.0.1:8000/api/v1/user/avatar?uid=1001

#### Trigger Condition
- Used an attack payload named uid-parameter-removal. Test rationale: Boundary bypass: remove uid parameter to see default/self behavior. Specific parameter overrides: No parameter overrides were observed.
- Trigger Payload: uid-parameter-removal

#### Risk Evidence (Key)
- Status Compare: baseline=200 / attack=200
- Similarity: 1.0
- Sensitive Hits: {}
- JSON Schema Overlap:
  - shared_keys=7
  - baseline_keys=7
  - attack_keys=7
  - overlap_ratio=1.00
- Evidence Highlight: No sensitive patterns such as phone numbers/emails/ID cards were matched.
- Reasons:
  - Baseline and attack both returned 200.
  - High body similarity detected (1.00).
  - JSON key structure is highly consistent between baseline and attack (shared=7/7, overlap=1.00).
  - Score capped at 70 because no sensitive data pattern was matched.
- Baseline Preview:
  - {"code":0,"data":{"avatar_url":"https://cdn.example.local/avatar/1001.png","bio":"I love secure coding and coffee.","nickname":"zs_dev","uid":"1001"},"msg":"ok"} 
- Attack Preview:
  - {"code":0,"data":{"avatar_url":"https://cdn.example.local/avatar/1001.png","bio":"I love secure coding and coffee.","nickname":"zs_dev","uid":"1001"},"msg":"ok"} 

#### Impact Analysis
- Attackers can perform sensitive operations or view unauthorized pages beyond their privileges.

#### Conclusion
- Comprehensive risk assessment level: Medium. Vulnerability exploitation successful, with evident privilege escalation behavior.

### Mitigation & Prevention
- Summary: Endpoint returns another user's data when uid parameter is omitted, indicating missing server-side ownership validation and insecure default behavior.
- Immediate Fixes:
  - Require uid parameter for all requests; return 400 Bad Request if missing
  - Implement server-side check: compare requested uid with authenticated user's ID; return 403 if mismatch
  - Remove default behavior that falls back to authenticated user's data when uid is omitted
  - Add authorization middleware that validates user ownership before processing request
- Engineering Hardening:
  - Implement deny-by-default authorization policy for all user resource endpoints
  - Use UUIDs instead of sequential numeric IDs to reduce enumeration risks
  - Create centralized authorization service with RBAC/ABAC rules for user data access
  - Add security unit tests verifying 403 responses for cross-account access attempts
  - Implement parameter validation middleware that rejects requests with missing required parameters
  - Design API to use path parameters (/api/v1/user/{uid}/avatar) instead of query parameters for resource identifiers
- Detection and Monitoring:
  - Implement audit logging for all user data access attempts, including requested and authenticated user IDs
  - Create alerts for repeated 403 authorization failures from single source
  - Monitor for parameter manipulation attacks in access logs
  - Implement automated security tests that verify authorization controls for all user resource endpoints
  - Add anomaly detection for cross-account access patterns outside normal behavior
- Suggestion Source: llm_mitigation_pass

### Finding 6

#### Risk Object
- API: GET http://127.0.0.1:8000/api/v1/file/download?file_id=f-1001

#### Trigger Condition
- Used an attack payload named admin-file-access, test reason: Attempt to access admin-level file by using a privileged file_id pattern.; specific override parameters: query={'file_id': 'admin-001'}
- Trigger Payload: admin-file-access

#### Risk Evidence (Key)
- Status Compare: baseline=206 / attack=500
- Similarity: 0.0648
- Sensitive Hits: {}
- JSON Schema Overlap:
  - shared_keys=0
  - baseline_keys=0
  - attack_keys=0
  - overlap_ratio=0.00
- Evidence Highlight: No sensitive patterns such as phone numbers/email addresses/ID cards were matched.
- Reasons:
  - Attack request triggered server error response.
- Baseline Preview:
  - partial-content:f-1001:nonce=476632
- Attack Preview:
  - {"detail":"invalid literal for int() with base 10: 'admin-001'","error":"internal server error","trace":"FileService.download -> parse_file_id -> resolver.map","type":"ValueError"} 

#### Impact Analysis
- Currently, there is a weak signal of unauthorized access; it is recommended to conduct further retesting and confirmation in conjunction with business semantics.

#### Conclusion
- Comprehensive risk assessment level: Low. Suspicious unauthorized access signals have been detected; it is recommended to repair and retest as soon as possible.

### Mitigation & Prevention
- Summary: Role-based access control (RBAC) for file categories; separate admin file storage with distinct authorization middleware; audit all admin file accesses.
- Immediate Fixes:
- Engineering Hardening:
- Detection and Monitoring:
- Suggestion Source: payload_hint

### Finding 7

#### Risk Object
- API: GET http://127.0.0.1:8000/api/v1/payment/cards?uid=1001

#### Trigger Condition
- Used an attack payload named uid-increment, test rationale: Horizontal escalation: numeric ID increment to access another user's payment cards.; specific override parameters: query={'uid': '1002'}
- Trigger Payload: uid-increment

#### Risk Evidence (Key)
- Status Compare: baseline=202 / attack=403
- Similarity: 0.1739
- Sensitive Hits: {}
- JSON Schema Overlap:
  - shared_keys=0
  - baseline_keys=0
  - attack_keys=0
  - overlap_ratio=0.00
- Evidence Highlight: No sensitive patterns such as phone numbers/email addresses/ID cards were matched.
- Reasons:
  - Attack request was blocked by authorization (401/403).
- Baseline Preview:
  - accepted:masked-card-view:uid=1001:nonce=233037
- Attack Preview:
  - {"error":"Forbidden"} 

#### Impact Analysis
- Currently, there are weak privilege escalation signals; it is recommended to conduct further retesting and confirmation in conjunction with business semantics.

#### Conclusion
- Comprehensive risk level assessment: Info. No clear evidence of successful privilege escalation has been found at this time.

### Mitigation & Prevention
- Summary: Validate that the authenticated user (from token) matches the 'uid' query parameter; implement ownership checks before returning data.
- Immediate Fixes:
- Engineering Hardening:
- Detection and Monitoring:
- Suggestion Source: payload_hint

### Finding 8

#### Risk Object
- API: GET http://127.0.0.1:8000/api/v1/system/announcements?id=1

#### Trigger Condition
- Used an attack payload named increment-id, test rationale: Horizontal escalation via numeric ID increment to access other announcements.; specific override parameters: query={'id': '2'}
- Trigger Payload: increment-id

#### Risk Evidence (Key)
- Status Compare: baseline=206 / attack=206
- Similarity: 0.6061
- Sensitive Hits: {}
- JSON Schema Overlap:
  - shared_keys=0
  - baseline_keys=0
  - attack_keys=0
  - overlap_ratio=0.00
- Evidence Highlight: No sensitive patterns such as phone numbers/email addresses/ID cards were matched.
- Reasons:
- Baseline Preview:
  - public-announcement:1:System maintenance:noise=3969
- Attack Preview:
  - public-announcement:2:Feature release:noise=4285

#### Impact Analysis
- Currently, there is a weak signal of unauthorized access. It is recommended to conduct further retesting and confirmation in conjunction with business semantics.

#### Conclusion
- Comprehensive risk level assessment: Info. No clear evidence of successful unauthorized access has been found at present.

### Mitigation & Prevention
- Summary: Implement ownership validation: ensure the authenticated user has explicit read permission for the requested announcement ID via server-side checks.
- Immediate Fixes:
- Engineering Hardening:
- Detection and Monitoring:
- Suggestion Source: payload_hint
