# Trellix ENS Firewall → Microsoft Defender (GCC High) migration

Maps a Trellix ENS Firewall XML export to native Microsoft Defender for Endpoint
firewall rules in **GCC High**, and stages them safely:

- Creates **one new** Defender configuration policy. Existing policies are never touched.
- Every rule it creates is **Disabled**. Nothing starts blocking or allowing traffic.
- The new policy has **zero device assignments**. No endpoint is affected.
- Re-running it does not create duplicates — it re-verifies the same policy.
- Rules that cannot be mapped automatically are listed as **Open**, with the reason.
  Nothing is guessed, assumed or silently dropped to inflate the mapped count.

## Requirements

- Windows with PowerShell 7.4+ (`pwsh -v`); see [aka.ms/powershell](https://aka.ms/powershell)
- A GCC High tenant ID and an account that can create Intune/Defender configuration policies
- Your own Trellix ENS Firewall XML export (not included in this repository)

## Step 1 — Download the files

Click the green **Code** button above → **Download ZIP**, then extract it anywhere on your
computer (for example your Desktop). You can also `git clone` this repo if you prefer.
Either way you'll end up with a folder containing `Deploy-TrellixFirewallRules.ps1` and a
`toolkit` subfolder — keep them together.

## Step 2 — Add your Trellix XML export

Copy your Trellix ENS Firewall export XML into **the same folder you just
downloaded/extracted** (easiest), or anywhere else on your computer. The script checks it
is byte-for-byte the exact file this mapping was built and reviewed against, so don't edit
or re-export it.

## Step 3 — Run the script

Open the downloaded folder, right-click inside it and choose **"Open in Terminal"** (or
open PowerShell and `cd` into the folder), then run:

```powershell
pwsh -NoProfile -File .\Deploy-TrellixFirewallRules.ps1 -TenantId "<your GCC High tenant ID>"
```

If you put the XML somewhere other than this folder, add `-XmlPath`:

```powershell
pwsh -NoProfile -File .\Deploy-TrellixFirewallRules.ps1 -TenantId "<your GCC High tenant ID>" -XmlPath "C:\path\to\YourExport.xml"
```

Want to see the rule counts first **without** signing in or changing anything? Add `-PrepareOnly`:

```powershell
pwsh -NoProfile -File .\Deploy-TrellixFirewallRules.ps1 -TenantId "<your GCC High tenant ID>" -PrepareOnly
```

## Step 4 — Sign in when prompted

The script prints a web address and a short code, for example:

```
To sign in, use a web browser to open the page https://login.microsoftonline.us/device and enter the code ABCD1234 to authenticate.
```

Open that address in any browser, enter the code, and sign in with an account that can
create Intune/Defender policies in your GCC High tenant.

## Step 5 — Wait for it to publish and verify

The script publishes the policy, then **reads it back from Microsoft** to confirm it
matches exactly and is still unassigned, before it tells you anything succeeded.

## Step 6 — Review the results — where the output report is

When it finishes, it saves **`Results-<your tenant id>.html`** in the same folder you ran
it from (next to `Deploy-TrellixFirewallRules.ps1`). That file is generated fresh by every
run — it is not something you download from this repo. Open it in any browser. It shows:

- **Mapped and deployed** — every Trellix rule name next to its exact new Defender rule
  name, and a direct link to the policy.
- **Open** — Trellix rules or rule groups that could not be mapped automatically, and the
  specific reason why.

`Results-template.html` in this repo is just the styling/layout used to build that report —
you never open it directly.

## Step 7 — After this runs

The new policy is **Disabled** and **unassigned** on purpose. Before turning any rule on
or assigning it to devices:

- Review each rule inside the policy in the Defender portal.
- Pick a small pilot group of devices to test with first.
- Separately review everything listed as **Open** in the results — it represents real
  Trellix configuration that did not have a safe automatic Defender equivalent.

## Troubleshooting

**It says the XML doesn't match / "does not match the file this mapping was reviewed against"**
This migration was built and reviewed against one specific export. If your file has since
been re-exported from Trellix (even with no visible changes), its checksum will differ and
the script stops rather than silently mapping against unreviewed data. Use the original
file, or have the mapping reviewed again against the new export.

**Can I run this more than once?**
Yes. It reuses the same policy rather than creating a duplicate, and re-verifies it is
still correct and unassigned.

**Does this turn anything on?**
No. Every rule it creates is Disabled, and the policy is never assigned to any device by
this script.

## Repository contents

| File | Purpose |
|---|---|
| `Deploy-TrellixFirewallRules.ps1` | The script you run. |
| `Results-template.html` | Styling used to generate your results report (not opened directly — see Step 6). |
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
