# Hardening guide

What an operator of a self-hosted DockVault does to run it safely, and what stays theirs to do. The
[README](../../README.md) explains each setting; this guide is the checklist and the reasons, and it says plainly
where the product's protection ends.

## Where the line is

DockVault protects what passes through the application: who may sign in, who may open which vault, what is
recorded and who is told. It cannot protect against whoever runs the server:

- **The operator can read Standard vaults outside the app.** `ENCRYPTION_KEY` opens every Standard vault's files
  and names; anyone with it and the volumes can read them without the app, and nothing is recorded or told.
  Zero-knowledge vaults are the exception: their keys never reach the server.
- **The operator can restore an old backup or edit the database.** A restore can undo a deletion, a release, a
  revocation or a record; an edit can change any row, and nothing in the app can show who made it.
- **The host, its network, its disks and its backups are the operator's.** Disk encryption, patching, SSH access,
  firewalling and backup custody are outside the app.

Treat `.env` and the backups as the most sensitive things you hold.

## The checklist

- **Keep `ENCRYPTION_KEY` safe, and off the host.** Back it up (a password manager, a safe); never rotate it on a
  vault that holds data.
- **Terminate TLS in front of the app**, and name your reverse proxy in `TRUSTED_PROXIES` so the audit log and the
  sign-in limits see real addresses.
- **Publish only what is used:** the web port, and the SFTP port only if SFTP is used. Keep PostgreSQL and Redis on
  the internal network; set `REDIS_PASSWORD` and `ALLOWED_HOSTS`.
- **Post-quantum SFTP.** `SFTP_KEX_POLICY=pq-preferred`, the default, agrees the hybrid ML-KEM exchange with every
  client that offers it (OpenSSH 9.9 and later). Before you set `pq-required`, look in the log of the container
  that runs SFTP for `kex.agreed.classical` lines: each one is a client that would then be refused. Under
  `pq-required` a server that cannot offer the hybrid exchange does not start SFTP, and in the one-container shape
  the whole vault stops with it.
- **Require a second factor for administrators.** Every compliance step asks for the password and an
  authenticator code, a recovery code or a passkey that verified the person (for an auditor who is not an
  administrator, only a passkey their auditor right was approved or last reconfirmed with) whatever the step-up
  settings say, but the rest of an administrator's work follows the step-up matrix in Settings. A few changes always ask for the password, and the second factor when the
  administrator has one, whatever the matrix says: how long records are kept, what the audit log records,
  acknowledging its integrity warnings, letting a sign-in last longer (a longer session timeout or "Stay
  signed in" limit), how people sign in, and changing or testing the mail server settings (a sending profile,
  or the SMTP settings saved with the general settings). The stored SMTP password goes only to the server it
  was entered for: pointing it at another server, port or username, or turning the certificate check off,
  needs the SMTP password entered again.
- **Keep sign-ins short.** Session Timeout is how long a sign-in lasts before the page asks whether to stay
  signed in; "Stay signed in for at most" (24 hours by default) is how long staying can keep one sign-in going.
- **Configure email.** Owners are told of access to their vaults in the app always, and by email only when the
  vault can send email; an owner who seldom signs in learns of it by email.
- **State a contact** in Settings (the recording notice's contact): it is the address every notice to a vault's
  owner gives for questions and objections.
- **Lock what must not change from the admin panel** with `SETTINGS_LOCKED_KEYS` (a key, or a group). The
  compliance settings are set in `.env` only. The groups `sso` and `webauthn` act differently: see
  [Sign-in](#sign-in-passkeys-and-single-sign-on).
- **Keep the images current** with `dockvault.py update`, and read the upgrade notes of each release.

## Sign-in: passkeys and single sign-on

Both are set under Settings, Sign-in methods. Each change there is saved on its own and asks for the
administrator's password, and the second factor when they have one. Both work only at the vault's address, the
first `ALLOWED_HOSTS` entry. Passkeys need an `https` host name (not an address reached by IP) with a certificate
browsers trust: Chrome and Edge refuse passkeys on a self-signed certificate the device does not trust. Single
sign-on needs an `https` address, and an IP address serves it where the provider accepts one as a redirect address
(Google does not). `python dockvault.py status` says whether passkeys can be made at the address, and why not.

- **Require passkeys where you want sign-ins that cannot be phished**, administrators first. Set **Passkeys** to
  **Required for roles** and choose the roles in **Roles that must have a passkey**, which is empty by default, so
  the mode alone requires nobody. Each account then has **Days to set a required passkey up** (14 by default),
  counted from its first sign-in under the requirement. The requirement waits while no passkey can be made at the
  vault's address. When a person's browser cannot make a passkey, the server's operator lets that one account in
  without it: `python dockvault.py accounts --action clear-passkey-requirement`, with the account's username typed
  twice (see the [README](../../README.md#account-changes-from-the-host)).
- **Keep The authenticator must verify the person on**, as it is by default. Off, a passkey that checked no PIN,
  fingerprint or face is one factor: the password always follows it, and it never counts for a compliance step-up.
- **Roles a passkey signs in alone** (user and external by default): for these roles a passkey that verified the
  person, and that the device keeps with the account, is the whole sign-in. Administrators and holders of the
  auditor right always type their password too. Empty the list to keep the password for everyone.
- **Roles whose passkeys must be device-bound** refuses a synced passkey for those roles when one is added and in
  a compliance step-up. Without direct attestation the authenticator's own word is taken for whether a key is
  synced.
- **Attestation** set to **Direct** checks the make of each new passkey against the root certificates in the file
  `WEBAUTHN_ATTESTATION_ROOTS` names, and **Allowed authenticator makes** can then limit new passkeys to the makes
  you list. Put only authenticator vendors' attestation roots in that file, never a general-purpose certificate
  authority. Only the HTTPS compose lets the server read the file. Passkeys added before direct attestation was
  turned on keep signing in, and no longer prove a compliance step-up.
- **Restrict every provider** to your organisation on its Access page: **Tenants** (Microsoft Entra ID),
  **Domains** (Google Workspace), **Required groups**, or the sign-up domain list when it is an allow-list. A
  provider makes accounts at a first sign-in, or links an existing account by its verified email, only when it
  says who may sign in. An Entra issuer already names your tenant, so a tenant there keeps nobody out: require a
  group, and in Entra let only assigned people use the app.
- **Keep the leaver rules on** (the provider's Sessions page, all on by default): back-channel logout; a refusal
  by the provider ends access here; the days a person may go without signing in through the provider (30; 0 turns
  it off), after which their SSH keys, temporary credentials and devices pause; and after those days or a refusal,
  the account signs in only through a provider (its password on the web and over SFTP, a passkey by itself, and
  Stay signed in after a sign-in made without a provider are refused). Microsoft Entra ID and Google send no
  back-channel logout, so for their people the days and the refusal are what end access. Turning a provider off
  during an incident gives nobody a password back: the accounts it held stay held.
- **Count a provider's second factor only on purpose** (off by default), and only with the `amr` or `acr` values
  you list. The Second factor page shows what the last test sign-in carried.
- **Administrators keep their password.** No administrator or holder of the auditor right is held to a provider.
  When a provider cannot be reached, an administrator signs in with the password (and the second factor), and can
  turn the provider off.

**Locking.** `SETTINGS_LOCKED_KEYS=sso` freezes the providers as they are: nothing is added, changed, turned on or
off, or removed in the panel, while reading them and running a test sign-in stay open. The passkey settings take
their `WEBAUTHN_*` values in `.env` (their defaults where none is set), and an administrator's change in the panel
replaces those unless the setting is locked: locking them (the group `webauthn`, `*`, or one key) holds the `.env`
value. Attestation and the allowed authenticator makes have no `.env` value: locked, they stay at none and any make.

**Going back below 0.36.0** reopens what 0.36.0 closes. People a provider refused, or whose days ran out, get their
password, SSH keys, temporary credentials and devices back. A passkey or a provider's second factor is no second
factor there, and a role's passkey requirement is not asked for. First disable the accounts of people who left,
and have each account whose second factor is a passkey or a provider's add an authenticator app. Each of the
release's upgrade conditions gives a query that finds them.

## Compliance access

Compliance access lets an auditor investigate other people's vaults in a case that a second, independent
administrator approves. It is on by default because a legal hold, which preserves files a court or a regulator
needs, is part of it. If you will never investigate a vault or hold one, turn it off:

```
COMPLIANCE_ACCESS=disabled
```

Turned off, active cases are suspended and nothing new can be granted, asked for, approved, opened or revealed;
legal holds already placed stay in force and can still be confirmed, reviewed and released. Turning it on again
needs no migration.

When you keep it on:

- **Grant the auditor right sparingly**, to people whose job is investigations, and let it expire
  (`COMPLIANCE_AUDITOR_GRANT_DAYS`, a year at most); renewing it is a new grant by two administrators.
- **Consider `COMPLIANCE_AUDITOR_NOT_ADMIN=true`**, so an auditor cannot also be an administrator.
- **Have auditors' accounts created by an administrator who did not make the others.** No administrator in the
  line of whoever created an auditor's account (one the creator made an administrator, directly or through others,
  or one who made the creator one) may approve that auditor's right or cases. Where one administrator made all the
  others and also creates the auditor's account, no administrator in the app can approve, and only the server's
  operator decides, on the host (`dockvault.py cases`).
- **Choose how vaults with a password are treated** (`COMPLIANCE_PASSWORD_VAULTS`): `refuse` (a case never opens
  them), `with_password` (the default: the auditor must give the password), or `override` (an approved case may
  open them without it). With `override`, an owner who sets a vault password is not protected from an
  investigation by it, and the owner's notice says so.
- **Keep exports off unless you need them** (`COMPLIANCE_EXPORT=disabled`): an export is a copy that leaves the
  vault.
- **Keep the record floor** (`COMPLIANCE_RECORD_MIN_DAYS`, six years by default): the records of a case outlive it.
  The server refuses to start when the audit log's ceiling (`PLAN_LOG_MAX_DAYS`) is shorter.
- **Tell your people** that compliance access exists and how it works: the page *What this vault records* has a
  section on it, filled from your settings.

### Owners are told at once: the tipping-off question

A case tells each owner of a vault it covers at the moment it is approved, in the app (and by email when the server
sends email and the owner has an address), and every file opened is listed for the owner as it happens. DockVault
offers no delayed or silent access.

Some laws forbid warning the person under investigation: anti-money-laundering rules on tipping-off, some
law-enforcement requests, and national restrictions under GDPR Art. 23. **Where the law forbids telling the owner,
do not open a case.** Take legal advice, and preserve the data by other means agreed with your counsel (a legal
hold also tells the owner). The purpose "Regulator or authority request" does not change this.

### What remains, by design

- **Two administrators acting together can open a vault.** The owner is told at once and sees every file opened:
  the product detects this; it cannot prevent it.
- **Two administrators made by the same administrator count as independent of each other.** If one administrator
  makes two others, one of them can create an account and propose its auditor right and the other approve it and
  its cases: the rule refuses an approver in the line of the account's creator, of the proposer or of the auditor,
  not one beside them. Refusing those too would leave the usual install, where the first administrator made the
  others, with no approver in the app. Every new administrator is announced to all the others, waits 14 days
  before approving anything, and the owner is told at once and sees every file opened.
- **What is shown can be captured.** A screenshot or a saved page is not recorded; the watermark on the viewer and
  the record of each file opened deter it.
- **Email is configured by administrators.** Only the notice in the app is guaranteed; the email's address is the
  one the owner had when the notice was written, and a copy goes to the previous one after a recent administrator
  change.
- **Choosing vaults without their names is clumsy for an auditor.** The vault picker shows a name only where the
  auditor can read the vault already: the names of other people's vaults are not disclosed before a case is
  approved.
- **The vault picker shows any administrator, and any auditor whose right is in force, an account's vaults**: for
  each, its type, whether it has a password, its number of files, its size and when it was made (an administrator
  needs this to place a legal hold). It never shows a vault's name to someone who could not read the vault anyway,
  and each look is recorded (`case_picker_viewed`, with the id of the account looked at; a look that finds no
  such account is recorded too, as a failure, without what was looked for).
- **An administrator a case concerns cannot see it on the Compliance page, but can learn of it from the Activity
  page**, which every administrator reads whole. The rows of compliance access are there with no vault or file
  name: a case asked for or approved, a hold placed (with the vault's id), and an auditor's look at the vault
  picker (with the id of the account whose vaults were listed). Such a row can tell that administrator that a case
  about them exists, even one not yet approved. Hiding those rows from the administrators they concern would make
  the log differ from one administrator to the next, so it is not done: weigh this before you open a case about an
  administrator.
- **A revealed name follows the vault's password as it is now**, as the names on the Activity page do: names
  recorded while a vault had a password can be revealed once its owner removes the password, and a vault given a
  password later no longer has any of its recorded names revealed, including those recorded before.

### What a legal hold refuses

While a legal hold stands on a vault, or what it kept waits for its purge (files and folders deleted from the
vault, and the old names of those renamed in it), the vault cannot be deleted, and a zero-knowledge vault's older
key versions are not retired: what was kept was sealed under them, and only their owner's keys open it. A case
about a person (its custodian) keeps their account as well: it cannot be deleted while the case's hold stands or
what the hold kept waits for its purge. Each refusal is recorded under the case (`hold_blocked_delete`), and says
why: to the vault's owner and to an administrator it names the case, while another manager of the vault refused a
retire is told only that a legal hold keeps it. A per-person erase waits while any confirmed hold stands or any
case is open, and says which case it waits for. A hold nobody has confirmed yet keeps what is deleted from its
vaults, which counts toward the deployment's storage limit (`MAX_STORAGE_GB`, or the lower limit set on the
Settings page), but holds no erase back: one person places it alone. One person can have at most five hold-only
cases waiting for confirmation at once. Without a storage limit (the default), what holds keep is bounded by the
free space the storage volume keeps (`MIN_FREE_SPACE_GB`: by default the larger of 2 GB and 5% of the volume,
never more than half of it nor more than 20 GB): uploads, SFTP writes and copies that would leave less are
refused, so deleting and uploading in turn in a held vault cannot fill the disk.

### Upgrading with SFTP in its own container

In the split profile (and the trial compose) the SFTP server runs in a container of its own. An SFTP server of an
older release does not know about legal holds and would delete what a hold keeps, so **a legal hold cannot be
placed while an SFTP server of another version may be running**: the page says so. Update the SFTP container
together with the web container, then place holds.

### Going back to an older release

While a legal hold stands, or what a hold kept (files, folders, the old names of renamed ones) waits for its purge,
a release before 0.34.0 would destroy it. From 0.33.1 on, an older release refuses to start on such data, and
`dockvault.py update` refuses the rollback. To roll back: release every hold on the Compliance page
(`dockvault.py cases` cannot release one), wait until what they kept is purged
(`COMPLIANCE_HOLD_PURGE_DELAY_DAYS` after the release), then start 0.34.0 or later once more so it removes the
marker. A release before 0.33.1 does not read the marker: never roll back that far while holds exist.

### Someone else giving access

When someone other than the owner gives another person access to a vault (a grant to the person or to their
department, adding them to a department, removing their own access row so their departments' wider access applies),
the vault's owner is told at once in the app, and by email too when that someone could not open the vault themselves
(an administrator who is not one of its members), this server sends email and the owner has an address. The notice
says who the person is, how old their account is, who created it and whether its password was set by someone else.
This is how an owner learns that an administrator made an account and gave it their vault.

### A data protection impact assessment

Investigating people's files is likely to need one. The [DPIA template](dpia-compliance-access.md) is filled in with
what the product does; you add your purposes, your legal basis, your people and your decision.
