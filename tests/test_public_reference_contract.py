"""Public deployment/reference contracts that must stay resolvable and data-safe."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

ROOT = Path(__file__).parents[1]
SOURCE_SUFFIXES = {".py", ".js", ".yml", ".yaml", ".md", ".sh", ".ps1", ".toml"}
SOURCE_ROOTS = ("app", "static", "deploy", ".github", "scripts")
TOP_LEVEL_SOURCES = (
    "README.md",
    ".env.example",
    "dockvault.py",
    "Dockerfile",
    "docker-entrypoint.py",
    "run_combined.py",
    "docker-compose.yml",
    "docker-compose.secure.yml",
)
REPO_REFERENCE = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"((?:docs|static|deploy|scripts|\.github)/"
    r"[A-Za-z0-9_./-]+\.[A-Za-z0-9]+)"
)


def _public_source_files():
    files = [ROOT / name for name in TOP_LEVEL_SOURCES]
    for name in SOURCE_ROOTS:
        directory = ROOT / name
        files.extend(
            path
            for path in directory.rglob("*")
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
        )
    return files


def test_public_source_references_resolve_to_shipped_files():
    references = []
    missing = []
    for source in _public_source_files():
        text = source.read_text(encoding="utf-8")
        for match in REPO_REFERENCE.finditer(text):
            reference = match.group(1).rstrip(".,:;)")
            references.append((source, reference))
            if not (ROOT / reference).is_file():
                missing.append(f"{source.relative_to(ROOT)} -> {reference}")

    assert len(references) >= 20, (
        "reference resolver did not scan the expected public source surface"
    )
    assert not missing, (
        "public source points at files that are not shipped:\n" + "\n".join(missing)
    )


def test_removed_setup_state_paths_have_no_runtime_consumer_or_mount():
    runtime_files = [
        *ROOT.joinpath("app").rglob("*.py"),
        ROOT / "dockvault.py",
        ROOT / "Dockerfile",
        ROOT / "docker-entrypoint.py",
        ROOT / "run_combined.py",
        ROOT / "deploy" / "docker-compose.yml",
        ROOT / "deploy" / "docker-compose.secure.yml",
    ]
    runtime = "\n".join(path.read_text(encoding="utf-8") for path in runtime_files)

    for dead_reference in (
        "SETUP_STATE_FILE",
        "setup_state.json",
        "/app/run",
        "/app/deployments",
    ):
        assert dead_reference not in runtime, (
            f"removed setup-state path still has a runtime consumer or Compose mount: "
            f"{dead_reference}"
        )


def test_manual_profile_transition_commands_render_safe_reconciliation():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Deployment modes: combined vs split", 1)[1].split(
        "## Update notifications", 1
    )[0]
    commands = [
        line.strip()
        for line in section.splitlines()
        if line.strip().startswith("docker compose ")
    ]

    assert commands == [
        "docker compose -f docker-compose.secure.yml --profile combined rm -s -f vault",
        "docker compose -f docker-compose.secure.yml up --build -d "
        "--force-recreate --remove-orphans",
        "docker compose -f docker-compose.secure.yml --profile split rm -s -f "
        "vault-api vault-sftp",
        "docker compose -f docker-compose.secure.yml up --build -d "
        "--force-recreate --remove-orphans",
    ]
    assert all("-v" not in command for command in commands)
    assert "exactly one value: `combined` or `split`" in section
    assert "Redis cache contents may be cleared" in section
    assert "asks to recreate it with\ndata loss, answer **no**" in section


def test_example_env_uses_only_current_setup_and_profile_semantics():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")

    for obsolete in ("COMPOSE_PROFILES=sftp", "CERT_MODE=", "--certs-only"):
        assert obsolete not in example
    assert re.search(r"(?m)^COMPOSE_PROFILES=combined$", example)
    assert "set RUN_SFTP=1" in example
    assert "--cert-mode selfsigned|letsencrypt|byo" in example
