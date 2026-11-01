# Data protection impact assessment: compliance access (template)

A template for the controller (the organisation running DockVault) to assess investigations of people's vaults
under GDPR Art. 35. The parts marked **[fill in]** are yours: your purposes, your legal basis, your people, your
decision. The rest describes what DockVault 0.34.0 does, so that you can check it against your deployment and
keep what applies. Review it whenever your settings or the way you investigate change.

| | |
|---|---|
| Controller | **[fill in]** |
| Data protection officer | **[fill in]** |
| Assessment owner, date, version | **[fill in]** |
| DockVault release and the settings in force | **[fill in: the release, and the `COMPLIANCE_*` lines of `.env`]** |

## 1. The processing

**What it is.** An *auditor* (an account two administrators gave the auditor right) can read the activity log,
reveal a name an event recorded in full (with a reason), and ask for a *case*: access to the files of named vaults
for a limited time, which an administrator independent of the auditor approves. A case can place a *legal hold*,
which keeps what is deleted from the vaults until it is released. A hold can also be placed without access.

**Purposes offered by the product.** Internal investigation, litigation or legal hold, regulator or authority
request, data-subject request, security incident, other. **[fill in: which you use, and for what]**

**Legal bases offered.** Legal obligation, public task, legitimate interests (with a reference to your assessment
of them). Consent is not offered. Special-category data (Art. 9) needs a condition of Art. 9(2)(b) to (j);
criminal-offence data (Art. 10) is marked as such. **[fill in: your basis for each purpose]**

**Whose data.** The owners of the vaults a case covers; the people whose data is in those files (colleagues,
customers, anyone); the people named in a case; the members of those vaults; the auditor and the administrators.
**[fill in: the categories of data your vaults hold]**

**What is recorded about the investigation.** Who asked and why (the justification, sealed at rest), who approved,
the vaults and folders covered, every file opened and every export (with a hash of its list), every name revealed
and its reason (sealed), every refusal. Kept for ever as the record of the case; its events at least
`COMPLIANCE_RECORD_MIN_DAYS` after it closes (six years by default). See *What this vault records* and the data
inventory (`docs/data-inventory.md`).

**Recipients.** The auditor; the administrators who approve; the owners (their notices). An export is a copy the
auditor takes out of the vault. **[fill in: who receives exports, and where they are kept]**

## 2. Necessity and proportionality

What the product does to keep an investigation to what is needed:

- **Two people for everything that gives power.** The auditor right needs a proposer and an independent approver; a
  case needs an approver independent of the auditor, of whoever proposed the auditor's right, of the people the case
  concerns and of whoever created or changed the auditor's account.
- **Limited in scope and time.** A case names its vaults (or folders) and may limit the files to a time range; its
  access lasts `COMPLIANCE_MAX_ACCESS_DAYS` at most at a time and `COMPLIANCE_MAX_TOTAL_DAYS` with extensions, each
  extension approved again. It can be narrowed, never widened: wider needs a new case.
- **Zero-knowledge vaults are never opened** (the server cannot). Vaults with a password follow
  `COMPLIANCE_PASSWORD_VAULTS`.
- **Exports** can be turned off (`COMPLIANCE_EXPORT`), and each one asks for the auditor's password and a code.
- **A view rate** (`COMPLIANCE_VIEW_RATE`) and **a daily cap on revealed names** (`COMPLIANCE_REVEALS_PER_DAY`).
- **Nothing is opened before the approval**, and nothing after the access ends.

**[fill in: why investigating vaults is necessary for each purpose; what less intrusive means you tried; how you
decide which vaults a case names]**

## 3. Transparency

- **The owner is told at once**, when a case is approved, in the app, and by email when the server sends email and
  the owner has an address (with a copy to the address before an administrator's recent change of it), with the
  case's number, purpose, legal basis, auditor and approver, how long it lasts, and the auditor's note to them;
  every file opened is listed for the owner as it happens, and the owner is told of extensions, narrowing, exports,
  the end and the close. **[fill in: whether this deployment sends email, and how you make sure owners have an
  address]**
- **Members of a covered vault** see a neutral banner: the vault is part of an authorised review until a date.
- **When anyone but the owner gives a person access** to an owner's vault, the owner is told in the app, with who
  that person is and where their account came from; by email too when the one who gave it could not open the vault
  themselves, this server sends email and the owner has an address.
- **When an auditor reveals a recorded name** from an owner's vault outside a case, the owner is told (once a day
  per auditor and vault) and sees each reveal on *Access to my vaults*: when, by whom and the reason's category.
- **The page *What this vault records*** describes compliance access as configured.
- **The product does not tell the people named in a case, or the people whose data is in the files.**
  **[fill in: how you inform them (Art. 13, 14), or the exemption you rely on]**

DockVault has no delayed or silent mode. Where a law forbids telling the person under investigation, do not open a
case (see the hardening guide).

## 4. Risks to the people concerned

| Risk | Likelihood and severity **[fill in]** | What the product does | What you do **[fill in]** |
|---|---|---|---|
| Access beyond what is needed (curiosity, a fishing expedition) | | Two-person approval, scope and time limits, every view recorded and shown to the owner | |
| Two administrators acting together | | The owner is told at once and sees every view: detected, not prevented | |
| An account made or taken over to approve | | The approver must be independent of the account's creator and of whoever changed its sign-in details; the right ends or is suspended when the auditor's sign-in details change | |
| The investigation becomes known to the wrong people | | Notices name no vault, file or folder; members see a neutral banner; administrators the case concerns cannot see it | |
| Copies leaving the vault | | Exports can be off; each is recorded with its list's hash and told to the owner | |
| Files deleted to defeat an investigation | | A legal hold keeps what is deleted, until released | |
| Records kept too long | | Case records for ever by default, events six years after the close | |
| The server's operator reading vaults outside the app | | Out of the product's reach: see the hardening guide | |

## 5. Measures and decision

**[fill in: the measures you add (policies, training, who may be an auditor, how cases are documented, how exports
are stored and destroyed), the residual risk, whether you consult the supervisory authority (Art. 36), the DPO's
advice, and the decision with its date and who took it]**
