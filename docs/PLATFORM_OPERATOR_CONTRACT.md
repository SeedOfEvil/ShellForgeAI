# Platform operator contract

ShellForgeAI uses one immutable platform-aware contract for generic operator
presentation and unsupported-platform dispatch. It is metadata, not an intent
router: `route_input`, `route_ask_intent`, and the bounded Windows classifiers
remain the authorities for interpreting operator text. The contract never
selects a collector, constructs a provider, validates commands, or executes an
action.

## Authority and API

`build_platform_operator_contract(info=None)` accepts an optional
`PlatformInfo`; its production default uses `detect_platform()`. It returns a
frozen `PlatformOperatorContract` containing `platform_system`, `display_name`,
`support_lane`, `route_family`, `local_evidence_available`, `summary_heading`,
`evidence_label`, `fallback_heading`, `visibility`, `unsupported_reason`, and
`next_safe_command`. Support-lane values come from the maintained
`support_status()` mapping.

## Deterministic matrix

| Platform | Display | Support lane | Route family | Local evidence | Visibility |
| --- | --- | --- | --- | --- | --- |
| Linux | Linux | `linux_docker_v1` | `linux_primary` | yes | `linux-docker-local-read-only` |
| Windows | Windows | `windows_read_only_doctor_v1` | `windows_read_only` | yes | `windows-local-read-only` |
| Darwin | macOS | `unsupported` | `unsupported` | no | `unsupported` |
| Unknown | this host | `unsupported` | `unsupported` | no | `unsupported` |

Generic presentation is pinned as follows:

| Platform | Summary heading | Evidence label | Fallback heading |
| --- | --- | --- | --- |
| Linux | Linux/Docker operator summary | Linux/Docker local read-only evidence | Linux/Docker read-only fallback |
| Windows | Windows operator summary | Windows local read-only evidence | Windows read-only fallback |
| Darwin | macOS operator support | No supported local operational evidence lane | Unsupported platform |
| Unknown | Operator support | No supported local operational evidence lane | Unsupported platform |

Specialized Docker triage and Windows status, service, performance, handoff,
prompt, and evidence-fallback renderers retain their maintained vocabulary.
Windows remains preview/early read-only support. The maintained bounded
`windows_read_only_doctor_v1` lane is supported on native Windows; this does not
imply Linux/Docker parity, mutation support, or availability of evidence that
was not observed. Windows evidence continues to report limitations and
unavailable categories truthfully. Windows is not promoted to
Linux/Docker V1 parity.

## Integration and precedence

Top-level `ask` first completes its maintained deterministic Windows,
receipt, recipe, status, report, triage, help, and mutation-refusal handling.
It then obtains the existing `route_ask_intent` decision. Only an already
selected evidence-backed route consults the contract. On Darwin or an unknown
platform, the shared renderer returns before provider construction, evidence
collection, prompt construction, or model use.

Interactive mode resolves the same contract once after workspace trust and
reuses it for the session. Existing control/shell guards, Windows routes,
mutation refusal, latest-context handling, and explicit routing remain ahead
of generic evidence fallback. An unsupported generic diagnosis, empty-context
health follow-up, or machine-health request returns before collectors and the
model. Plain conversation, help, command explanation/review, and explicit
non-evidence handlers remain available.

The same session contract gates every maintained interactive local-evidence
boundary: `/health`, evidence-producing CLI dispatch, routed diagnosis,
refusal-adjacent log diagnosis, pending/deeper follow-ups, firewall diagnosis,
service diagnosis, and generic health collection. Metadata/control dispatch
such as `version` remains available. Generic session summaries render the
contract's summary heading, evidence label, and visibility; specialized Docker
and Windows renderers remain unchanged.

The unsupported renderer is deterministic. It identifies the safe display
name and support lane, reports `read_only=true` and
`mutation_performed=false`, says that no supported local evidence lane was
selected and no evidence was collected, and offers only
`shellforgeai platform doctor --json`.

## Safety and non-goals

The contract has no user-text parameter, I/O, collector, provider/model,
filesystem, network, persistence, command-validation, approval, receipt, or
execution dependency. Natural-language mutation refusal retains priority and
its maintained wording. No route phrases, collectors, commands, or model
behavior are changed.

Command-suggestion validation remains a later consumer (PR330). Timed or
progressive evidence-first responses remain PR331. Golden-path command and
advanced-help presentation remains PR332.

## Semantic operator-parity audit

The versioned [Linux/Windows operator parity contract](OPERATOR_PARITY_CONTRACT.md)
defines cross-platform semantic targets and audits normalized observations.
Existing Linux/Docker and Windows route-family specialization remains valid:
platform-native evidence does not mean identical collectors. The parity contract
is not an intent router, and its harness delegates runtime observations to the
maintained routing authorities. It does not change routing or runtime behavior.
