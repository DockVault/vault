"""Admin bootstrap: seed the FIRST admin account from ADMIN_USERNAME/ADMIN_PASSWORD.

Kept in its own module (no import-time side effects) so the seed-once logic can be exercised directly
against a database session in tests, without importing the whole API server (which bootstraps
credentials at import).

Seed-ONCE-per-deployment is enforced by a marker row in ``system_settings`` (key
``admin_bootstrap``). Once bootstrap has run - or an admin already exists - the marker is set and this
refuses to seed again. That closes an injection path: previously the seed was keyed on the *username*,
so changing ADMIN_USERNAME (+ ADMIN_PASSWORD) in ``.env`` and restarting would mint a brand-new admin.
"""

from app.core.config import settings

ADMIN_BOOTSTRAP_MARKER = "admin_bootstrap"


def bootstrap_admin(db) -> str:
    """Seed the first admin from ADMIN_USERNAME/ADMIN_PASSWORD, exactly once per deployment.

    Returns a short status string (for logging and tests):
      ``seeded``               - a new admin was created and the marker set.
      ``marked-existing``      - an admin already existed; the marker was set, nothing seeded.
      ``already-bootstrapped`` - the marker was already present; nothing done (a later ADMIN_USERNAME
                                 change can NOT mint a new admin).
      ``no-password``          - no admin exists and no password is configured; NOT marked, so a later
                                 boot with a password can still bootstrap the first admin.
    Commits its own change (marker and/or user) on the seeding paths.
    """
    from app.core.models import RoleEnum, SystemSetting, User

    def _marked():
        return (
            db.query(SystemSetting)
            .filter(SystemSetting.key == ADMIN_BOOTSTRAP_MARKER)
            .first()
            is not None
        )

    def _mark(how):
        if not _marked():
            db.add(SystemSetting(key=ADMIN_BOOTSTRAP_MARKER, value={"how": how}))

    # Already bootstrapped once -> never seed again (this is the injection this closes).
    if _marked():
        return "already-bootstrapped"

    # An admin already exists (created via the API, or a deployment predating this marker): record the
    # marker so future env-driven seeds are refused, but do NOT create another admin.
    if db.query(User).filter(User.role == RoleEnum.ADMIN).first():
        _mark("pre-existing-admin")
        db.commit()
        return "marked-existing"

    # No admin yet. Match the config guard's emptiness definition: a whitespace-only password is blank.
    # Do NOT set the marker here, so a deployment configured without a bootstrap password can still be
    # bootstrapped on a later boot once one is provided.
    if not (settings.admin_password or "").strip():
        return "no-password"

    from app.services.auth_service import AuthService

    # ORDERING IS LOAD-BEARING: create the admin FIRST, then set the marker. create_user commits the
    # user itself, so if it raises, _mark is never reached and no orphaned marker is left (the next
    # boot re-tries). Setting the marker before the admin exists could leave a marker with no admin ->
    # env-based bootstrap permanently disabled with no way in. Do not reorder these.
    AuthService(db).create_user(
        username=settings.admin_username,
        email=settings.admin_email or "admin@local",
        password=settings.admin_password,
        role=RoleEnum.ADMIN,
    )
    _mark("seeded")
    db.commit()
    print(f"[OK] Bootstrapped admin user '{settings.admin_username}' from environment")
    return "seeded"
