# Release signing configuration

GoReleaser builds/publishes releases inside `Bit-Precise/agentd`. Native Windows
and macOS jobs perform signing directly; no reusable workflow in
`Bit-Precise/actions` is used. Azure Variables and Apple Variables/Secrets remain
at GitHub **organization scope**, with access granted to `agentd`. Signing jobs
use the repository's `release-signing` environment to constrain allowed refs;
the environment does not hold duplicate signing credentials.

Both architectures of Windows EXE/MSI and macOS TGZ/PKG are signed in the
`release-signing` GitHub environment. Tagged builds fail if any required setting
or signature is missing. Unsigned PR/main builds do not access signing secrets.
The 26 product filenames are unchanged.

## Azure Artifact Signing

Compilation and packaging do not require Azure login. GitHub is the OIDC issuer
only when the Windows signing job requests a short-lived Azure credential;
Azure verifies which repository/environment is asking to sign. This is unrelated
to `agents` user login/OIDC. Ordinary CI and macOS signing have no `id-token`
permission or Azure authentication.

Use a dedicated Microsoft Entra application, without a client secret. Assign only
**Artifact Signing Certificate Profile Signer**
(`2837e146-70d7-4cfd-ad55-7efa6464f958`) on the existing certificate profile.
Contributor or subscription-wide signing access is unnecessary.

The federated credential must have:

| Field | Exact value |
|---|---|
| issuer | `https://token.actions.githubusercontent.com` |
| subject | `repository_owner_id:295183371:repository_id:1423467115:environment:release-signing` |
| audience | `api://AzureADTokenExchange` |

The repository overrides the organization template with:

```json
{"use_default": false, "include_claim_keys": ["repository_owner_id", "repository_id", "context"]}
```

GitHub's `context` becomes `environment:release-signing` for a job using that
environment. This binds Azure access to the immutable organization ID, this
repository ID, and the signing environment, independently of branch/tag names.
It does not require `job_workflow_ref`, which ordinary jobs do not provide.
The organization's existing template is not changed, so other repositories are
unaffected. A new repository needs its own explicitly added federated credential.

The environment allows only branch `main` and tag pattern `v*`. No required
reviewer/manual approval is added. Protect release tags through the repository's
normal maintainer permissions/rulesets.

Use these **organization Variables**, not environment-level duplicates:

| Variable | Value |
|---|---|
| `AZURE_CLIENT_ID` | Existing application: `b8d78a6f-09be-4622-9b1e-31d5f937f7e4` |
| `AZURE_TENANT_ID` | `434591f5-2f86-4991-8784-d800512dd8fb` |
| `AZURE_SUBSCRIPTION_ID` | `e4a93474-db18-4218-b22d-356788c3d84d` |
| `AZURE_SIGNING_ENDPOINT` | `https://wus2.codesigning.azure.net/` |
| `AZURE_SIGNING_ACCOUNT` | `bitprecisellc` |
| `AZURE_SIGNING_PROFILE` | `bitprecisellc` |

These IDs identify resources and are not secrets. The existing PublicTrust
profile must remain Active. Its Signer role is scoped only to that profile.

`scripts/configure-azure-signing.py` defaults to a **read-only plan** using the
actual repository IDs. `--apply` configures the repository template, main/v*
environment policy, the named FIC in the existing application, and the profile
Signer assignment if missing. It does not create applications, service
principals, client secrets, paid resources, organization variables or secrets,
and does not modify the organization OIDC template.

```sh
python3 scripts/configure-azure-signing.py \
  --tenant-id 434591f5-2f86-4991-8784-d800512dd8fb \
  --subscription-id e4a93474-db18-4218-b22d-356788c3d84d \
  --application-id b8d78a6f-09be-4622-9b1e-31d5f937f7e4 \
  --resource-group artifactsigning --account bitprecisellc --profile bitprecisellc \
  --endpoint https://wus2.codesigning.azure.net/
```

The existing `credential-github` was migrated from the former shared-workflow
subject to the exact repository/environment subject above. The helper refuses
to overwrite a different named credential unless its current subject exactly
matches an explicitly supplied `--replace-subject`. For another repository,
choose a different `--credential-name` to add trust without replacing agentd's
credential. The applying operator needs permission to manage this application's
FIC, the repository environment/OIDC settings and the profile role assignment;
the signing workload receives none of those administrative permissions.

The workflow uses [Azure login v3.1.0](https://github.com/Azure/login/releases/tag/v3.1.0)
and [Artifact Signing v2.0.0](https://github.com/Azure/artifact-signing-action/releases/tag/v2.0.0),
pinned to their verified release commits. The latter authenticates using the
Azure CLI session created by GitHub OIDC. It signs with SHA256 plus Microsoft's
RFC3161 timestamp service, `http://timestamp.acs.microsoft.com`, as recommended
by the official action. The signed timestamp response is cryptographically
validated by Windows; this URL is not a credential transport. Signing dependency
caches and trace logging are disabled. Azure login clears its session after the
job; there is no long-lived Azure client secret in the workflow.

EXE signing finishes before the MSI is assembled. `-RequireSigned` checks Windows
Authenticode `Valid`, signer certificate, timestamp certificate, and `signtool
verify /pa /all /tw`. The final signed MSI is installed on the native runner and
its installed EXE SHA256 must match the separately released signed EXE.

## Apple Developer ID and notarization

Export the **Developer ID Application** and **Developer ID Installer** identities,
including their private keys, as password-protected PKCS#12 (`.p12`) files. Both
must belong to the same Apple developer team. Create an App Store Connect **team
API key** usable with `notarytool` (issuer ID + key ID + `.p8`); this workflow uses
team keys, not individual keys or an Apple ID/app-specific password.

To prepare these on macOS:

1. In **Keychain Access → Certificate Assistant → Request a Certificate From a
   Certificate Authority**, create a CSR and choose **Saved to disk**. Keep the
   generated private key in your local login keychain.
2. In [Apple Developer Certificates](https://developer.apple.com/account/resources/certificates/list),
   use the intended developer team to create **Developer ID Application** and
   **Developer ID Installer** certificates using that CSR. If your team restricts
   creation, its Account Holder/admin must grant the necessary access or perform
   this step. Download and import both `.cer` certificates into Keychain Access.
3. In Keychain Access **My Certificates**, verify each identity expands to show
   its corresponding private key. Export each identity separately as `.p12`,
   using a strong nonempty password. Exporting `.cer` alone is insufficient.
   Record each certificate's full identity name and the team ID shown in it.
4. In [App Store Connect → Users and Access](https://appstoreconnect.apple.com/access/users),
   open **Integrations → App Store Connect API → Team Keys**, create a team key
   permitted to submit notarizations, and record its Key ID and Issuer ID.
   Download the `.p8` key once and store it securely. The team must enable API
   access if the section is not available. Do not create an Individual key for
   this workflow, which explicitly uses an issuer ID.
5. Open [organization Actions secrets](https://github.com/organizations/Bit-Precise/settings/secrets/actions)
   and the adjacent Variables tab. Add the credentials below with access for
   `agentd`; keep them at organization scope. The `release-signing` environment
   only restricts deployments to branch `main` and tags `v*`.

Set these **organization Variables**:

| Variable | Value |
|---|---|
| `APPLE_APPLICATION_IDENTITY` | Full `Developer ID Application: NAME (TEAMID)` identity |
| `APPLE_INSTALLER_IDENTITY` | Full `Developer ID Installer: NAME (TEAMID)` identity |
| `APPLE_TEAM_ID` | 10-character developer team ID |
| `APPLE_NOTARY_KEY_ID` | App Store Connect API key ID |
| `APPLE_NOTARY_ISSUER_ID` | App Store Connect API issuer UUID |

Set these **organization Secrets** using GitHub's Secrets UI or local `gh secret
set` with stdin. Never paste `.p12`, `.p8` contents or passwords into chat, shell
arguments, committed files, logs or artifacts:

| Secret | Content |
|---|---|
| `APPLE_APPLICATION_P12_BASE64` | Single-line base64 of Application `.p12` |
| `APPLE_APPLICATION_P12_PASSWORD` | Nonempty password for Application `.p12` |
| `APPLE_INSTALLER_P12_BASE64` | Single-line base64 of Installer `.p12` |
| `APPLE_INSTALLER_P12_PASSWORD` | Nonempty password for Installer `.p12` |
| `APPLE_NOTARY_KEY_P8_BASE64` | Single-line base64 of team API key `.p8` |

For example, from a trusted local shell, pass encoded key bytes directly to
GitHub without displaying them:

```sh
base64 < /secure/path/application.p12 | tr -d '\n' |
  gh secret set APPLE_APPLICATION_P12_BASE64 --org Bit-Precise --visibility selected --repos agentd
# Use the Secrets UI or gh secret set's interactive prompt for passwords.
```

The temporary signing keychain is explicitly selected for codesign/productsign.
The runner's previous keychain search list is restored, and no default keychain
is replaced. PKCS#12 exports are removed immediately after import. The `.p8`
file and ephemeral keychain are deleted even if a command fails. Hosted signing
runners must remain ephemeral: forced VM termination cannot execute cleanup.

Notarization accepts two inputs per architecture: a ZIP containing the exact
signed CLI distributed in TGZ, and the signed PKG. Both must return `Accepted`.
PKG is stapled and validated, then assessed by Gatekeeper. Raw CLI binaries and
TGZ archives do not support stapling; the notarized CLI's ticket is resolved
online from its CDHash. Prefer PKG for offline Gatekeeper validation. SHA256SUMS
is created only after these steps, and hashes the final stapled PKG.

## Verification without publishing

After configuring both providers, run **Build and release → Run workflow →
main → signing_validation=true**, or:

```sh
gh workflow run build.yml --repo Bit-Precise/agentd --ref main -f signing_validation=true
# Validate only Windows while Apple credentials are pending:
gh workflow run build.yml --repo Bit-Precise/agentd --ref main -f signing_validation=true -f signing_platform=windows
```

This performs signing, notarization, native installation, and checksums but does
not create a GitHub Release. It uses the configured signing services and their
normal quotas/billing. PRs and other branches cannot opt into this mode.

If a private credential/certificate is missing, signed validation is expected to
fail. Portable tests and unsigned CI validate tooling and installers; they do
not constitute evidence of a successful cloud signature or Apple notarization.

References: [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc),
[Azure OIDC](https://github.com/Azure/artifact-signing-action/blob/v2.0.0/docs/OIDC.md),
[Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution),
[Apple custom notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
