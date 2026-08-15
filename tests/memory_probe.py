"""Sampling a container's memory while something is happening to it.

A transfer's cost is a *peak*, and a peak is only visible while the transfer is in flight. Reading
before and after instead measures what is left over afterwards, which is a different and much
smaller number: a download that held the whole file showed a rise of 0.3 MB when sampled that way
and 15.1 MB when sampled properly — a factor of fifty, in the direction that makes a broken
implementation look fixed.

Two memory tests were written with before-and-after readings and both passed against builds that
predated the work they were meant to guard. This exists so that cannot happen again.

Page cache is excluded throughout, because it is not what a process allocated and it dwarfs what is:
on a stack that has moved a few gigabytes it reaches 2.5 GB while allocation sits under 200 MB.
"""

import os
import subprocess
import threading
import time

import pytest


# Reads the container's own cgroup in a loop. Both layouts are handled: v2 exposes
# `memory.current`, v1 `memory/memory.usage_in_bytes`, and a probe that assumes one silently
# reports zero on the other — which is its own way of making a test pass for no reason.
_SAMPLE_LOOP = (
    'while true; do '
    'if [ -r /sys/fs/cgroup/memory.current ]; then '
    'cur=$(cat /sys/fs/cgroup/memory.current); '
    'fil=$(awk \'/^inactive_file /{a=$2} /^active_file /{b=$2} END{print a+b}\' '
    '/sys/fs/cgroup/memory.stat); '
    'else cur=$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes); '
    'fil=$(awk \'/^total_inactive_file /{a=$2} /^total_active_file /{b=$2} END{print a+b}\' '
    '/sys/fs/cgroup/memory/memory.stat); fi; '
    'echo $((cur - ${fil:-0})); done'
)

MIN_SAMPLES = 50


class CgroupSampler:
    """Reads a container's allocated memory continuously until stopped.

    Use as a context manager around the operation being measured. `rise` is the peak minus the
    lowest reading taken *in the same window*, not against a baseline captured earlier: Python does
    not return freed memory promptly, so a container that has already done work rests higher than a
    later run's peak and comparing across windows can produce a negative cost.
    """

    def __init__(self, container=None):
        self.container = container or os.environ.get("VAULT_API_CONTAINER", "vault-api")
        self._proc = None
        self._thread = None
        self._stop = False
        self.samples = []

    def __enter__(self):
        try:
            self._proc = subprocess.Popen(
                ["docker", "exec", self.container, "sh", "-c", _SAMPLE_LOOP],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except (OSError, subprocess.SubprocessError) as exc:
            pytest.skip(f"cannot sample {self.container}: {exc}")
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()
        time.sleep(1.0)          # let a resting baseline accumulate before the work starts
        if not self.samples:
            self.__exit__(None, None, None)
            pytest.skip(f"no readings from {self.container}; its cgroup may not be readable")
        return self

    def _read(self):
        for line in self._proc.stdout:
            if self._stop:
                break
            line = line.strip()
            if line.isdigit():
                self.samples.append(int(line))

    def __exit__(self, *exc):
        self._stop = True
        if self._proc is not None:
            self._proc.kill()
        time.sleep(0.2)
        return False

    @property
    def rise(self):
        """Peak minus the floor of this same window."""
        if len(self.samples) < MIN_SAMPLES:
            pytest.skip(
                f"only {len(self.samples)} readings from {self.container}; too few to call "
                "anything a peak")
        return max(self.samples) - min(self.samples)
