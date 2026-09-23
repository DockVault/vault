"""The web container's healthcheck, run as a program:

    python -B -m app.core.healthcheck        exit 0 = healthy, 1 = not

It asks the running app's own /health and fails when either:

* /health does not answer 2xx -- the app is down, or its schema is incomplete (the one state /health
  answers non-2xx for); or
* /health says the SFTP half that runs in THIS container has stopped (``sftp`` is one of
  SFTP_DOWN, which the app reads from the SFTP heartbeat). In the combined profile the web and SFTP
  halves share one container, so a hung SFTP server makes the container unhealthy -- as it already
  makes ``vault-sftp`` unhealthy in the split profile.

Every other /health state still passes, as it did before: a database or Redis outage is reported as
``degraded`` in the body, and restarting the container would not fix it. ``external`` (split: SFTP
is another container's) and ``disabled`` (a web-only vault) are healthy by definition.

Standard library only, so a check costs a Python start-up and one local request.
"""
import json
import os
import ssl
import sys
import urllib.request

# The /health values meaning "SFTP was meant to run in this container and is not serving": the
# half never beat at all, or its heartbeat went stale. The ONE list: /health's degraded summary
# reads it too.
SFTP_DOWN = ("unreachable", "unresponsive")


def health_url():
    """The app's own /health, over the scheme and port this container serves it on."""
    https = os.getenv("API_USE_HTTPS", "false").strip().lower() == "true"
    port = os.getenv("API_PORT", "8000").strip() or "8000"
    return ("https" if https else "http") + "://localhost:" + port + "/health", https


def main(opener=urllib.request.urlopen) -> int:
    url, https = health_url()
    # A self-check against localhost: the certificate is for the public name, not "localhost".
    context = ssl._create_unverified_context() if https else None
    try:
        with opener(url, context=context, timeout=8) as response:
            body = json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 -- unreachable, non-2xx or unreadable: all mean not healthy
        return 1
    if isinstance(body, dict) and body.get("sftp") in SFTP_DOWN:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
