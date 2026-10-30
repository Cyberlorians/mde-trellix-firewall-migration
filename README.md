# Trellix ENS Firewall → Microsoft Defender (GCC High) migration

Maps a Trellix ENS Firewall XML export to native Microsoft Defender for Endpoint
firewall rules in **GCC High**, and stages them safely:

- Creates **one new** Defender configuration policy. Existing policies are never touched.
- Every rule it creates is **Disabled**. Nothing starts blocking or allowing traffic.
- The new policy has **zero device assignments**. No endpoint is affected.
- Re-running it does not create duplicates — it re-verifies the same policy.
- Rules that cannot be mapped automatically are listed as **Open**, with the reason.
  Nothing is guessed, assumed or silently dropped to inflate the mapped count.

## Start here

Open **[Instructions.html](Instructions.html)** in a browser. It walks through:

1. Downloading these files
2. Adding your Trellix XML export
3. Running `Deploy-TrellixFirewallRules.ps1` with your GCC High tenant ID
4. Signing in (Microsoft device-code sign-in)
5. Reviewing the generated `Results-<tenant>.html` report

## Requirements

- Windows with PowerShell 7.4+ (`pwsh -v`); see [aka.ms/powershell](https://aka.ms/powershell)
- A GCC High tenant ID and an account that can create Intune/Defender configuration policies
- Your own Trellix ENS Firewall XML export (not included in this repository)

## Repository contents

| File | Purpose |
|---|---|
| `Deploy-TrellixFirewallRules.ps1` | The script you run. |
| `Instructions.html` | Step-by-step guide with a live command builder. |
| `Results-template.html` | Styling used to generate your results report (not opened directly). |
| `toolkit/` | The review/mapping engine and the guarded Microsoft Graph publisher. |

Your XML export and the `work/` and `Results-*.html` files the script generates are
specific to your tenant and are intentionally excluded from version control (see
`.gitignore`) — they are never meant to be committed here.

## Safety model

This is intentionally a **staging** tool, not an activation tool:

- No assignment, activation, update-existing-policy or delete endpoint is exposed.
- Before publishing, it re-reads the live Microsoft Graph schema and re-validates the plan.
- After publishing, it reads the policy back from Microsoft and confirms the persisted
  settings match exactly, and that the policy still has zero assignments, before
  reporting success.
- Cloud acceptance and read-back are not proof of equivalent packet filtering or endpoint
  enforcement. Treat the result as a reviewed staging artifact, and run your own pilot
  before assigning any rule to devices.
