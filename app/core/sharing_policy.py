"""Pure resolution + evaluation of the Sharing feature's admin policy.

No app imports, so it unit-tests in isolation; callers read the SystemSetting('global') blob and the
ShareTag rows and pass plain values in (mirrors temp_passcode_policy.py / password_policy.py). No
enforcement lives here.

FAIL-CLOSED where it matters:
  - the feature master switch defaults OFF and stays OFF for any non-bool stored value;
  - a tag's create-allowlist DENIES by default — a user who is not explicitly allowed, not in an
    allowed department, and not covered by auto-enroll cannot create with the tag (a blocklist entry
    always wins); an inactive tag is never creatable.
"""

# The claim-audience vocabulary a tag may permit. "anyone_internal" = any AUTHENTICATED internal user
# who holds the share link (NEVER anonymous). A tag's allowed_audiences is a subset of this tuple.
AUDIENCES = ("users", "departments", "anyone_internal")

# Hard floor for a tag's lifetime ceiling: at least 1 minute. There is NO app cap (a tag's ceiling may
# be years) — the admin owns that bound.
MIN_LIFETIME_MINUTES = 1


def sharing_enabled(cfg) -> bool:
    """Master switch. FAIL-CLOSED: default False, and False for any non-bool stored value (strict
    `is True`, so a stray truthy string can't turn the feature on)."""
    return (cfg or {}).get("sharing_enabled") is True


def normalize_audiences(value) -> list:
    """Keep only recognized audience tokens, de-duplicated, order-stable. A typo, an unknown token, or
    a non-list collapses to [] (or drops the bad entry) so an unrecognized audience can never silently
    widen who may claim a share."""
    if not isinstance(value, (list, tuple)):
        return []
    seen, out = set(), []
    for a in value:
        if a in AUDIENCES and a not in seen:
            seen.add(a)
            out.append(a)
    return out


def _as_id_set(value) -> set:
    """A JSON list of id strings -> a set of str(id); tolerant of a non-list (-> empty set), so a
    malformed allowlist field fails CLOSED (matches nothing) rather than raising."""
    if not isinstance(value, (list, tuple)):
        return set()
    return {str(x) for x in value}


def user_can_create_with_tag(tag, user_id, user_group_ids) -> bool:
    """Evaluate a tag's create-allowlist for a user. Governs who may CREATE shares with the tag.

    FAIL-CLOSED, evaluated in this order:
      1. an inactive tag        -> never creatable
      2. user in blocked_user_ids -> DENY (the blocklist wins over allow rules)
      3. user in allowed_user_ids -> ALLOW
      4. any of the user's groups in allowed_department_ids -> ALLOW
      5. auto_enroll_new_users is True -> ALLOW (implicit allow for everyone not blocked)
      6. otherwise -> DENY

    `tag` is a mapping of the ShareTag fields (is_active, blocked_user_ids, allowed_user_ids,
    allowed_department_ids, auto_enroll_new_users). `user_id` is a str/uuid; `user_group_ids` is an
    iterable of the user's group ids. This is applied to EVERY user uniformly — there is no admin
    bypass, so an admin who wants to create shares must be allow-listed (or auto-enrolled).
    """
    if not tag.get("is_active", False):
        return False
    uid = str(user_id)
    if uid in _as_id_set(tag.get("blocked_user_ids")):
        return False
    if uid in _as_id_set(tag.get("allowed_user_ids")):
        return True
    user_gids = {str(g) for g in (user_group_ids or [])}
    if user_gids & _as_id_set(tag.get("allowed_department_ids")):
        return True
    return bool(tag.get("auto_enroll_new_users", False))


def user_matches_claim_audience(claim_audience, audience_user_ids, audience_department_ids,
                                user_id, user_group_ids) -> bool:
    """Whether a user may CLAIM a share, given its claim-audience. Governs REDEMPTION (distinct from the
    tag's create-allowlist, which governs who may CREATE). FAIL-CLOSED: an unknown audience returns False.
      - 'anyone_internal' -> any authenticated internal user (who holds the link)
      - 'users'           -> the user id must be in audience_user_ids
      - 'departments'     -> the user must belong to one of audience_department_ids
    Ids compare as strings; a malformed (non-list) audience field matches nothing."""
    if claim_audience == "anyone_internal":
        return True
    uid = str(user_id)
    if claim_audience == "users":
        return uid in _as_id_set(audience_user_ids)
    if claim_audience == "departments":
        user_gids = {str(g) for g in (user_group_ids or [])}
        return bool(user_gids & _as_id_set(audience_department_ids))
    return False


def _clamp_default(default, cap):
    """A default must never exceed its cap. cap None = unlimited (the default stands as given). If a
    cap exists, an unlimited default (None) or one above the cap is clamped down to the cap."""
    if cap is None:
        return default
    if default is None or default > cap:
        return cap
    return default


def tag_effective_limits(tag) -> dict:
    """The create-time limit envelope the share modal enforces, clamped so a default never
    exceeds its cap and the lifetime default sits within [1, ceiling]. Pure; reads the tag's
    *_cap / *_default / lifetime fields."""
    max_life = tag.get("max_lifetime_minutes") or MIN_LIFETIME_MINUTES
    max_life = max(MIN_LIFETIME_MINUTES, int(max_life))
    default_life = tag.get("default_lifetime_minutes") or max_life
    default_life = min(max(1, int(default_life)), max_life)
    return {
        "max_lifetime_minutes": max_life,
        "default_lifetime_minutes": default_life,
        "max_recipients_cap": tag.get("max_recipients_cap"),
        "max_recipients_default": _clamp_default(tag.get("max_recipients_default"), tag.get("max_recipients_cap")),
        "max_downloads_cap": tag.get("max_downloads_cap"),
        "max_downloads_default": _clamp_default(tag.get("max_downloads_default"), tag.get("max_downloads_cap")),
    }


def resolve_share_limits(tag, requested):
    """Resolve a share's effective limits from the tag policy + the creator's requested overrides.

    Returns (limits, error): `limits` is {lifetime_minutes, max_recipients, max_downloads, view_only}
    and `error` is None, OR (None, message) — the caller maps a message to a 400. Rules:
      - If the tag forbids customization (`allow_custom` False), the requested values are IGNORED and
        the tag defaults are used (a caller cannot widen a locked tag).
      - Otherwise each requested value is honored only WITHIN the tag's cap: a request ABOVE a cap is an
        ERROR (not a silent clamp), so the creator learns the share wasn't what they asked for. A
        requested view-only is honored only if the tag allows view-only (a tag with force_view_only
        MANDATES view-only regardless of the request or allow_custom). `None`/absent falls to the
        tag default. `max_recipients`/`max_downloads` caps of None mean unlimited (any positive value).
    Caps/defaults are read via tag_effective_limits (defaults already clamped to their caps)."""
    eff = tag_effective_limits(tag)
    allow_custom = bool(tag.get("allow_custom", True))
    req = requested or {}

    def _bounded(default, cap, req_val, name):
        if not allow_custom or req_val is None:
            return default, None
        try:
            v = int(req_val)
        except (TypeError, ValueError):
            return None, f"{name} must be an integer"
        if v < 1:
            return None, f"{name} must be at least 1"
        if cap is not None and v > cap:
            return None, f"{name} exceeds the tag cap ({cap})"
        return v, None

    life, err = _bounded(eff["default_lifetime_minutes"], eff["max_lifetime_minutes"],
                         req.get("lifetime_minutes"), "lifetime_minutes")
    if err:
        return None, err
    max_recip, err = _bounded(eff["max_recipients_default"], eff["max_recipients_cap"],
                              req.get("max_recipients"), "max_recipients")
    if err:
        return None, err
    max_dl, err = _bounded(eff["max_downloads_default"], eff["max_downloads_cap"],
                           req.get("max_downloads"), "max_downloads")
    if err:
        return None, err

    if tag.get("force_view_only"):
        # The tag MANDATES view-only on every share it mints: ignore the creator's request and
        # allow_custom entirely (the other limits above are still resolved normally).
        view_only = True
    else:
        view_only = bool(tag.get("default_view_only", False))
        if allow_custom and req.get("view_only") is not None:
            vo = bool(req["view_only"])
            if vo and not bool(tag.get("allow_view_only", True)):
                return None, "this tag does not allow view-only shares"
            view_only = vo

    return {"lifetime_minutes": life, "max_recipients": max_recip,
            "max_downloads": max_dl, "view_only": view_only}, None
