"""Container output is rotated on a running stack: what Docker applied to each container of the stack the suite runs
against (the compose files' logging block, json-file at DOCKER_LOG_MAX_SIZE x DOCKER_LOG_MAX_FILE, 10m x 5 when the
.env sets neither)."""
import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.integration

CONTAINERS = ("VAULT_API_CONTAINER", "VAULT_DB_CONTAINER", "VAULT_REDIS_CONTAINER", "VAULT_SFTP_CONTAINER")
DEFAULTS = {"VAULT_API_CONTAINER": "vault-api", "VAULT_DB_CONTAINER": "vault-db",
            "VAULT_REDIS_CONTAINER": "vault-redis", "VAULT_SFTP_CONTAINER": "vault-sftp"}


@pytest.mark.parametrize("variable", CONTAINERS)
def test_each_container_of_the_stack_rotates_its_output(variable):
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    name = os.environ.get(variable, DEFAULTS[variable])
    r = subprocess.run(["docker", "inspect", "-f", '{{.HostConfig.LogConfig.Type}} {{index .HostConfig.LogConfig.Config '
                        '"max-size"}} {{index .HostConfig.LogConfig.Config "max-file"}}', name],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0 and "No such object" in r.stderr and variable == "VAULT_SFTP_CONTAINER":
        pytest.skip("this stack runs no separate SFTP container")
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["json-file", "10m", "5"], (name, r.stdout)
