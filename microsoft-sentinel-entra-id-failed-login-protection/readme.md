# microsoft sentinel entra id failed login protection

a microsoft azure security automation project for detecting repeated failed microsoft entra id sign-in attempts,
auditing authentication activity, integrating mfa-related telemetry, and orchestrating incident response through 
microsoft sentinel and logic apps.
the project deliberately separates **identity enforcement** from **security monitoring**:
* **microsoft entra id smart lockout** handles temporary authentication lockouts.
* **microsoft sentinel** detects and correlates suspicious authentication activity.
* **kql** provides the detection logic.
* **sentinel automation rules** trigger response workflows.
* **azure logic apps / sentinel playbooks** orchestrate incident response.
* **microsoft graph powershell** provides administrative and emergency account-management operations.

## architecture
                         microsoft entra id
                              │
              ┌───────────────┼────────────────┐
              │               │                │
              ▼               ▼                ▼
        sign-in logs     smart lockout        mfa
              │               │                │
              │          authentication       │
              │          enforcement          │
              │               │                │
              └───────────────┼────────────────┘
                              │
                              ▼
                    microsoft sentinel
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
        failed login detection      password spray
              kql rule                 detection
                 │                         │
                 └────────────┬────────────┘
                              │
                              ▼
                           incident
                              │
                              ▼
                     automation rule
                              │
                              ▼
                    logic app / playbook
                              │
              ┌───────────────┼────────────────┐
              │               │                │
              ▼               ▼                ▼
            enrich          audit            notify
          user / ip         event             soc
                              │
                              ▼
                    high-confidence event??
                              │
                         ┌────┴────┐
                         │         │
                        no        yes
                         │         │
                        end        ▼
                              microsoft graph
                                   │
                                   ▼
                            disable account

## security model
the project uses two separate mechanisms for two different purposes.

### identity enforcement
microsoft entra id smart lockout is responsible for protecting authentication against repeated incorrect passwords.
the intended policy for this project is:
failed attempts: 3
lockout duration: 15 minutes
smart lockout should remain the primary mechanism for temporary authentication lockout rather than implementing a custom disable → wait → enable loop in a logic app.

### security monitoring
microsoft sentinel monitors the authentication telemetry and detects patterns such as:
multiple failed attempts against one account = possible brute force
multiple accounts targeted from one ip = possible password spray
repeated mfa failures = possible mfa abuse
multiple authentication signals = security incident
this separation prevents the SIEM from unnecessarily becoming the identity control mechanism.

# components
## 1. microsoft entra id
microsoft entra id provides the identity and authentication layer.
relevant components include:
* sign-in logs
* smart lockout
* multi-factor authentication
* conditional access
* user account state
authentication telemetry is forwarded to microsoft sentinel for security monitoring.

## 2. microsoft entra smart lockout
smart lockout provides the actual temporary authentication lockout.
target configuration:
lockout threshold: 3 failed attempts
lockout duration: 900 seconds
900 seconds = 15 minutes
smart lockout is intentionally separate from the sentinel detection rule.
the sentinel rule answers:
"has suspicious authentication activity occurred?"
smart lockout answers:
"should this authentication attempt be temporarily blocked?"

## 3. microsoft sentinel
sentinel acts as the siem and security orchestration layer.
it receives entra authentication telemetry and evaluates it using kql analytics rules.
primary detections include:
### failed login detection
detects more than three failed sign-in attempts against the same user within a 15-minute window.
### password spray detection
detects authentication failures affecting multiple users from the same source ip.
### mfa-related detection
monitors repeated mfa-related authentication failures and suspicious authentication behavior.

## 4. kql
kusto query language is used for sentinel detection logic.
the query deliberately returns additional context so that the resulting sentinel incident contains useful information for investigation.

## 5. sentinel analytics rules
analytics rules convert kql queries into sentinel detections.
the analytics rule creates a sentinel incident when the detection condition is met.

## 6. sentinel automation rules
automation rules determine what happens after sentinel generates an incident.
this keeps detection and response logic separate.

## 7. logic app / sentinel playbook
the playbook provides automated incident orchestration.
the normal three-failure scenario does **not** disable the entra account through the playbook.
temporary authentication protection is handled by smart lockout.
graph-based account disabling is reserved for confirmed or high-confidence incidents.

## 8. microsoft graph powershell
microsoft graph powershell is used for administrative operations that should not be embedded directly into the kql detection.
for emergency response, a separate script can disable an account
this operation is intentionally separate from smart lockout.

## more info
a key design principle in this project is separating **detection**, **authentication enforcement**, and **incident response**.

| function                 | technology                |
| ------------------------ | ------------------------- |
| authentication           | microsoft entra id        |
| temporary lockout        | entra smart lockout       |
| mfa                      | entra mfa                 |
| access policy            | conditional access        |
| authentication telemetry | entra sign-in logs        |
| detection                | kql                       |
| siem                     | microsoft sentinel        |
| incident automation      | sentinel automation rules |
| orchestration            | logic apps / playbooks    |
| administrative response  | microsoft graph           |
| scripting                | powershell                |

a single powershell loop could theoretically monitor events and disable accounts, but that would duplicate functionality 
already provided by azure's identity and security services.
this follows the separation of responsibilities between the azure services.

# security considerations
## false positives
a user can legitimately generate several failed authentication attempts.
the sentinel incident should provide additional context before stronger administrative actions are taken.
useful context includes:
* source ip
* number of affected users
* application
* authentication method
* geographic information
* device information
* conditional access results
* mfa activity
* historical behavior

## password spraying
an attacker may distribute attempts across multiple accounts instead of repeatedly attacking one account.
for this reason, a second detection should analyze failures by ip address:
this complements the per-user detection.

## mfa considerations
mfa should be treated separately from password failures.
mfa-related queries should use the authentication fields and event values available in the organization's actual 
entra sign-in logs rather than assuming that every tenant exposes identical event descriptions.

## permissions
the project should follow least-privilege principles.
production deployments should use managed identities or service principals where appropriate instead of embedding credentials in scripts.
secrets should never be committed to git.

## testin
testing should be performed in a dedicated test environment where possible.
test 1:
one user + repeated failures

test 2:
multiple users + same source ip

test 3:
repeated mfa failures

test 4:
successful authentication after failures

test 5:
confirmed compromised account

test 6:
false-positive / legitimate user

potential extensions from this template include:
* microsoft defender xdr integration
* user and entity behavior analytics
* threat intelligence enrichment
* ip reputation checks
* geoip enrichment
* device-risk correlation
* conditional access risk signals
* automated teams/soc notifications
* ticket creation
* automated high-confidence account disablement
* microsoft graph api integration
* terraform/bicep deployment
* github actions ci/cd
* sentinel content hub integration
* workbook for authentication monitoring

  will add stuff later
