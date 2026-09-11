# Known Limitations

Owner: PM and Security
Status: all limitations remain release inputs, not waivers.

| Limitation / unsupported surface | Threshold or constraint | Safe fallback | Review trigger / owner |
|---|---|---|---|
| Hosts other than Windows 11 24H2 x64 build 26100 NTFS | exact match only | observe nothing; `HOST_COMPATIBILITY_UNSUPPORTED` | host change / PM+Security |
| Agent/Desktop/source other than 0.20.5/0.17.0/`a251e87d826f4ef7c75a8927d5304e24cf43ef54` | exact match | fail closed | pinned release update / Compatibility reviewer |
| Python outside >=3.11,<3.14, manifest !=2, API !=1 | exact match | deny load/preflight | package update / Build |
| Project-local plugin discovery | accidental activation prohibited | unified user-plugin bundle inspection only | Hermes contract change / Security |
| Combined-process topology | never enforcement eligible | observe-only | out-of-process sole-writer proof / Security |
| Clean Windows service/SID/SDDL/ACL/DPAPI-NG/IPC proof | WP5 external evidence absent | `EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED` | authorized clean-host run / Security |
| Accessibility manual AT matrix | Narrator/NVDA/manual browser evidence absent | automated contract-ready only; typed unsupported/manual route | authorized AT session / Accessibility reviewer |
| Artifact open actions on unsupported hosts | no false open success | `ARTIFACT_LOCATOR_UNSUPPORTED` plus canonical locator/manual route | host capability available / Product Secretary |
| Production signing/trust/secrets | repository keys are fixtures | no production use | authenticated production authority / Security |
| Pilot thresholds | stage-specific 7-day, 100-command, and 20-schedule thresholds are not externally executed | remain at prior safe stage | threshold packet complete / named stage reviewers |
| External effects | adapters/tests are fixtures; unknown outcomes cannot retry | manual Effects reconciliation | provider authority available / Effects reviewer |
| Installation, migration, activation, deployment, retirement | none authorized | inspect/build only | exact separate Owner decision |
| Independent completion review/Owner acceptance | absent | completion rows remain BLOCKED | authenticated eligible audit and Owner acceptance |

Operational constraints: no direct database repair, no mutation credential in Hermes/Desktop, no reuse of approvals/nonces, no policy or trust rollback below floor, no secret values in prompts/cards/logs/repository, and no claim that build/test success authorizes installation or activation.