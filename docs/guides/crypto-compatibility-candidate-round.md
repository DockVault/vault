# Running a crypto-compatibility candidate round

The suite marked `crypto_compatibility` is not ordinary test coverage and does not run in CI. It is
a **release-candidate procedure**: evidence that one exact container, built from one exact source
tree, still reads every persisted format the project has ever written.

Reading that evidence back later only means something if the run was bound to a specific candidate.
That is what the `CRYPTO_COMPAT_*` variables are for, and why the suite refuses to guess: with none
of them set it **skips** (an ordinary suite run claims nothing and should not fail on a claim it was
never asked to make); with only some of them set it **fails** (a partial declaration is a provenance
check that cannot be trusted, and must not be silently downgraded to a skip by unsetting one name).

Everything below runs against a throwaway stack on your own machine. It touches no registry, no
remote host, and no shared database. Copy the commands as they are — every variable used is assigned
somewhere above its use.

---

## 1. Freeze the tree you are testing

The tree hash — not the branch, not the commit — is the identity the round is bound to.

```bash
cd <checkout>
git add -A
TREE=$(git write-tree)
echo "$TREE"
```

`git add -A` first, and do not edit the checkout again until the round finishes. The tree hash comes
from the **index**, but one of the gates re-hashes the crypto source files from the **working tree**
and compares them with the copies inside the container. If those drift apart, the round fails —
correctly, but confusingly.

## 2. Export that exact tree and build from the export

Do not build from the working directory. `git archive` guarantees the build context contains the
tree you just hashed and nothing else — no stray files, no editor droppings, no `.ruff_cache`.

```bash
ROUND=compat-$(date +%Y%m%d-%H%M%S)
EXPORT=/tmp/$ROUND
mkdir -p "$EXPORT" && git archive "$TREE" | tar -x -C "$EXPORT"

IMAGE=dockvault-vault-candidate:$TREE
docker build -t "$IMAGE" --build-arg OCI_REVISION="$TREE" "$EXPORT"
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
echo "$IMAGE_ID"
```

`OCI_REVISION` becomes `org.opencontainers.image.revision` on the image, and a gate asserts it
equals `$TREE`. That is what lets a later reader tell which tree produced an image without trusting
a note written beside it.

## 3. Configure an isolated round

Three things must be overridden, and none of them are handled by the Compose project name:

- **Container names.** `deploy/docker-compose.yml` pins `container_name: vault-db|redis|api|sftp`.
  These are *not* namespaced by `-p`, so a second stack collides with any existing one by name.
- **Volume names.** The volumes are declared with explicit `name:` built from
  `VAULT_VOLUME_PREFIX`. Also not namespaced by `-p`. This variable — not the project name — is what
  makes the teardown in §7 safe.
- **The image.** `vault-api` carries a `build:` section, so if you do not point `DOCKVAULT_IMAGE` at
  your candidate, Compose will happily build its own image from the working directory: exactly what
  §2 exists to prevent.

Two container **labels** are also mandatory. A gate asserts `com.dockvault.test-round` and
`com.dockvault.candidate-tree` on the API container; no service sets them, so the override must.

```bash
HTTP_PORT=29850     # any free loopback port; the compose default 8200 is hardcoded, so override it
SFTP_PORT=29851

cat > "$EXPORT/round.override.yml" <<YAML
services:
  vault-db:
    container_name: $ROUND-db
  vault-redis:
    container_name: $ROUND-redis
  vault-api:
    container_name: $ROUND-api
    image: $IMAGE
    build: !reset null
    labels:
      com.dockvault.test-round: "$ROUND"
      com.dockvault.candidate-tree: "$TREE"
    ports: !override
      - "127.0.0.1:$HTTP_PORT:8000"
  vault-sftp:
    container_name: $ROUND-sftp
    image: $IMAGE
    build: !reset null
    ports: !override
      - "127.0.0.1:$SFTP_PORT:2222"
YAML
```

The published port must be a **loopback** address. A gate rejects `0.0.0.0` and any non-loopback
binding: a candidate holding test data must not be reachable from the network.

Now the round's own environment. `deploy/docker-compose.yml` requires several values and aborts the
`up` without them, and running it directly (rather than through the repo-root include) needs
`--env-file` pointed at the file explicitly.

```bash
ADMIN_PW=$(openssl rand -hex 16)
cat > "$EXPORT/.env" <<ENV
VAULT_DB_PASSWORD=$(openssl rand -hex 16)
ENCRYPTION_KEY=$(openssl rand -base64 32 | tr '+/' '-_')
JWT_SECRET_KEY=$(openssl rand -hex 32)
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=$ADMIN_PW
VAULT_VOLUME_PREFIX=$ROUND
DOCKVAULT_IMAGE=$IMAGE
ENVIRONMENT=development
RATE_LIMIT_LOGIN_ATTEMPTS=100000
RATE_LIMIT_VAULT_ATTEMPTS=100000
RATE_LIMIT_VAULT_ATTEMPTS_ADMIN=100000
RATE_LIMIT_SFTP_KEY_ATTEMPTS=100000
RATE_LIMIT_API_DEFAULT=100000
RATE_LIMIT_API_AUTH=100000
RATE_LIMIT_API_UPLOAD=100000
RATE_LIMIT_API_DOWNLOAD=100000
ENV

cd "$EXPORT"
docker compose --env-file .env -p "$ROUND" \
  -f deploy/docker-compose.yml -f round.override.yml up -d
```

`DATABASE_URL`, `ENCRYPTION_KEY` and `JWT_SECRET_KEY` are hard startup requirements: without them
the API exits with `required-secret-missing` and the health-gated `up` fails on the API's own
dependency. `ENCRYPTION_KEY` must additionally be a valid Fernet key — 32 bytes of **URL-safe**
base64 — which is what the `tr` is for. Plain `openssl rand -base64` emits `+` and `/`, and Fernet
rejects those at startup.

The rate-limit budgets are raised because the shipped defaults are sized for a deployment, not a
test run: five logins per five minutes and ten auth requests per minute. A suite that authenticates
hundreds of times trips them, and the failure surfaces as `429` inside an unrelated fixture rather
than as anything resembling a limit. They are raised to a **high finite** number rather than
disabled, so the limiter still executes on every request — a round should not quietly change which
code paths run. This is a harness setting; it is not a claim about production configuration.

Record the exact inventory before testing — it is what makes the teardown in §7 checkable:

```bash
docker ps -a --filter "label=com.docker.compose.project=$ROUND" --format '{{.Names}}\t{{.Image}}'
docker volume ls  --format '{{.Name}}' | grep "^$ROUND"
docker network ls --format '{{.Name}}' | grep "^$ROUND"
```

## 4. Declare the round and run the gates

Run from the **checkout**, not the export: the source-hash gate compares the container's files
against the checkout it runs in.

```bash
cd <checkout>
export VAULT_BASE_URL=http://127.0.0.1:$HTTP_PORT
export VAULT_ADMIN_USER=admin
export VAULT_ADMIN_PASS="$ADMIN_PW"

export CRYPTO_COMPAT_ROUND_ID="$ROUND"
export CRYPTO_COMPAT_COMPOSE_PROJECT="$ROUND"
export CRYPTO_COMPAT_API_CONTAINER="$ROUND-api"
export CRYPTO_COMPAT_EXPECTED_IMAGE_ID="$IMAGE_ID"
export CRYPTO_COMPAT_EXPECTED_TREE="$TREE"
export CRYPTO_COMPAT_EXPECTED_PORT="$HTTP_PORT"

# Several suites set state directly through `docker exec <name> psql|redis-cli`. They default to
# the names "vault-db", "vault-redis", "vault-api", "vault-sftp" -- which belong to whichever stack
# claimed them first, NOT to your round. Point them at the round's containers.
export VAULT_DB_CONTAINER="$ROUND-db"
export VAULT_REDIS_CONTAINER="$ROUND-redis"
export VAULT_API_CONTAINER="$ROUND-api"
export VAULT_SFTP_CONTAINER="$ROUND-sftp"
export VAULT_SFTP_PORT="$SFTP_PORT"   # else the SFTP suites SKIP against the default 2322

pytest -m crypto_compatibility
```

The admin credentials are passed as environment variables because the fixtures otherwise fall back
to the checkout's `.env`, which is not the round's.

The container overrides deserve emphasis. If no `vault-db` exists the tests fail loudly and you fix
it. But if some **other** stack on the machine happens to be running one, they succeed while writing
to the wrong database — the round then reports on state it never created, and the other stack
quietly acquires rows nobody asked for. Set them before the first run, not after a confusing one.

`VAULT_SFTP_PORT` fails the other way, and is easier to miss for it: the SFTP suites probe the
default `2322`, find nothing, and **skip**. A run that reports "54 skipped" and no failures looks
successful while having tested no SFTP at all. Check the skip list, not just the exit code.

`VAULT_BASE_URL` and `CRYPTO_COMPAT_EXPECTED_PORT` are cross-checked against the container's actual
published binding, so a URL pointing at a *different* healthy instance fails rather than quietly
testing the wrong thing.

## 5. What the round proves, and what it does not

Bound to the exact candidate:

- **The instance is the candidate.** Its image ID equals `$IMAGE_ID`; the image's revision label and
  the container's `com.dockvault.candidate-tree` both equal `$TREE`; and the four crypto-carrying
  source files hashed *inside* the container match the checkout. A stale, foreign, reused, or
  differently mapped instance fails here rather than producing evidence under the wrong name.
- **It reads what was written before it.** Pinned Standard-vault blobs — current GCM chunk streams
  and legacy Fernet ones — decrypt to their expected plaintext inside that runtime.

Selected by the same marker but **not** bound to the candidate, which is fine as long as nobody
claims otherwise:

- The envelope-format and update-proof suites are `unit`-marked and run entirely offline. They test
  the code in the checkout; they never speak to the container.
- The temporary-credential and zero-knowledge boundary suites run over HTTP against
  `VAULT_BASE_URL`, but they do not consult the provenance fixture. They prove behaviour of
  whatever is answering on that port.

In practice that is the same container, because §4 sets one base URL — but it is a consequence of
how you ran it, not something the suite verifies.

## 6. Never patch a running candidate

`docker cp` into a live candidate — or an edit through a bind mount — breaks the property the whole
procedure exists for: the image no longer corresponds to the tree, and every hash the gates compare
becomes a statement about something that was never built. It has also, in practice, silently failed
to take effect.

If a fix is needed, start again from §1 with a new tree hash. Rounds are cheap; a round whose
evidence cannot be trusted is worse than no round.

## 7. Tear the round down

```bash
cd "$EXPORT"
docker compose --env-file .env -p "$ROUND" \
  -f deploy/docker-compose.yml -f round.override.yml down -v
docker image rm "$IMAGE"

# Absence recheck — each of these should print nothing.
docker ps -a        --format '{{.Names}}' | grep "^$ROUND"
docker volume ls    --format '{{.Name}}'  | grep "^$ROUND"
docker network ls   --format '{{.Name}}'  | grep "^$ROUND"
```

The `-v` is safe **only** because `VAULT_VOLUME_PREFIX` gave this round its own volume names and the
override file is passed again on teardown so Compose resolves the same set. Drop either and `-v` can
reach volumes that are not yours. Never run a bare `docker compose down -v`, and never `docker
system|volume|image prune`, on a machine that carries anything else.
