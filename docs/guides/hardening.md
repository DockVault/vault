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
- **Require a second factor for administrators.** Every compliance step asks for the password and an
  authenticator or recovery code whatever the step-up settings say, but the rest of an administrator's work follows
  the step-up matrix in Settings.
- **Configure email.** Owners are told of access to their vaults in the app always, and by email only when the
  vault can send email; an owner who seldom signs in learns of it by email.
- **State a contact** in Settings (the recording notice's contact): it is the address every notice to a vault's
  owner gives for questions and objections.
- **Lock what must not change from the admin panel** with `SETTINGS_LOCKED_KEYS` (a key, or a group). The
  compliance settings are set in `.env` only.
- **Keep the images current** with `dockvault.py update`, and read the upgrade notes of each release.

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
  and each look is recorded (`case_picker_viewed`, with the id of the account looked at).
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
retire is told only that a legal hold keeps it. A per-person erase waits while any hold stands or any case is
open, and says which case it waits for.

### Upgrading with SFTP in its own container

In the split profile (and the trial compose) the SFTP server runs in a container of its own. An SFTP server of an
older release does not know about legal holds and would delete what a hold keeps, so **a legal hold cannot be
placed while an SFTP server of another version may be running**: the page says so. Update the SFTP container
together with the web container, then place holds.

### Going back to an older release

While a legal hold stands, or what a hold kept (files, folders, the old names of renamed ones) waits for its purge,
a release before 0.34.0 would destroy it. From 0.33.1 on, an older release refuses to start on such data, and
`dockvault.py update` refuses the rollback. To roll back: release every hold (on the Compliance page or with
`dockvault.py cases`), wait until what they kept is purged (`COMPLIANCE_HOLD_PURGE_DELAY_DAYS` after the release),
then start this version once more so it removes the marker. A release before 0.33.1 does not read the marker: never roll back that far while holds exist.

### Someone else giving access

When someone other than the owner gives another person access to a vault (a grant to the person or to their
department, adding them to a department, removing their own access row so their departments' wider access applies),
the vault's owner is told at once in the app, and by email too when that someone could not open the vault themselves
(an administrator who is not one of its members). The notice says who the person is, how old their account is, who
created it and whether its password was set by someone else. This is how an owner learns that an administrator made
an account and gave it their vault.

### A data protection impact assessment

Investigating people's files is likely to need one. The [DPIA template](dpia-compliance-access.md) is filled in with
what the product does; you add your purposes, your legal basis, your people and your decision.
