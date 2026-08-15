"""How many transfers are carried at once, and what happens to the ones that arrive after.

Each transfer costs a bounded amount now, which is what makes a limit on their number meaningful.
Before this, nothing counted them: a hundred simultaneous downloads were all attempted.

The behaviour that matters is at the edges. A caller arriving at a full deployment must wait rather
than be dropped; a caller that waits too long must be told to come back rather than be handed
something that reads like a broken file; and the ceiling must be a real ceiling, including when
slots are released twice or released by something that never took one.
"""

import asyncio
import threading

import pytest

from app.core.transfer_admission import TransferAdmission, TransferBusy


pytestmark = pytest.mark.unit


def _run(coro):
    """Run an async body on a loop of its own, in a thread of its own.

    `asyncio.run` refuses if a loop is already running in the calling thread, and in the full
    integration lane something upstream leaves one running -- these tests then fail for a reason
    that has nothing to do with what they are testing. A unit test should not depend on ambient
    loop state at all, so it brings its own thread.
    """
    outcome = {}

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            outcome["value"] = loop.run_until_complete(coro)
        except BaseException as exc:                # noqa: BLE001 - re-raised on the caller
            outcome["error"] = exc
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                loop.close()

    thread = threading.Thread(target=_worker)
    thread.start()
    thread.join(timeout=60)
    assert not thread.is_alive(), "the async body did not finish"
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def test_transfers_up_to_the_limit_are_admitted_immediately():
    async def _go():
        gate = TransferAdmission(limit=3, max_waiting=5, wait_seconds=5)
        for _ in range(3):
            await gate.acquire()
        assert gate.stats()["in_flight"] == 3
    _run(_go())


def test_a_transfer_arriving_at_a_full_deployment_waits_rather_than_failing():
    """The queue is the point: a burst should be served, not refused."""
    async def _go():
        gate = TransferAdmission(limit=1, max_waiting=4, wait_seconds=5)
        held = await gate.acquire()

        admitted = []

        async def _late():
            await gate.acquire()
            admitted.append(True)

        waiter = asyncio.create_task(_late())
        await asyncio.sleep(0.05)
        assert not admitted, "the second transfer should be waiting, not admitted"
        assert gate.stats()["waiting"] == 1

        gate.release(held)
        await asyncio.wait_for(waiter, timeout=2)
        assert admitted == [True], "the waiting transfer was never admitted"
        assert gate.stats()["waiting"] == 0
    _run(_go())


def test_a_caller_that_waits_too_long_is_told_to_come_back():
    """Not dropped, and not disguised as a failure: a distinct outcome carrying an interval."""
    async def _go():
        gate = TransferAdmission(limit=1, max_waiting=4, wait_seconds=0.2)
        await gate.acquire()

        with pytest.raises(TransferBusy) as refused:
            await gate.acquire()

        assert refused.value.retry_after >= 1, "a refusal without an interval is not actionable"
        assert refused.value.limit == 1
    _run(_go())


def test_the_waiting_room_is_bounded_and_refuses_before_joining():
    """An unbounded queue is an unbounded cost, and a doomed caller should learn now, not later."""
    async def _go():
        gate = TransferAdmission(limit=1, max_waiting=2, wait_seconds=5)
        held = await gate.acquire()

        waiters = [asyncio.create_task(gate.acquire()) for _ in range(2)]
        await asyncio.sleep(0.05)
        assert gate.stats()["waiting"] == 2

        # The third finds the waiting room full and is refused straight away, rather than after
        # the full timeout.
        start = asyncio.get_running_loop().time()
        with pytest.raises(TransferBusy):
            await gate.acquire()
        assert asyncio.get_running_loop().time() - start < 1.0, (
            "a refusal for a full queue should be immediate, not delayed by the wait timeout")

        gate.release(held)
        first = await asyncio.wait_for(waiters[0], timeout=2)
        gate.release(first)
        second = await asyncio.wait_for(waiters[1], timeout=2)
        gate.release(second)
    _run(_go())


def test_releasing_a_slot_nobody_took_does_not_raise_the_ceiling():
    """A stray release would hand out capacity above the configured limit, silently.

    That is the failure this whole gate exists to prevent, arriving through the gate itself.
    """
    async def _go():
        gate = TransferAdmission(limit=2, max_waiting=0, wait_seconds=0.1)
        gate.release(object())          # never issued
        gate.release(None)
        held = await gate.acquire()
        gate.release(held)
        gate.release(held)              # the same token twice

        await gate.acquire()
        await gate.acquire()
        with pytest.raises(TransferBusy):
            await gate.acquire()
        assert gate.stats()["in_flight"] == 2
    _run(_go())


def test_a_released_slot_is_reusable():
    async def _go():
        gate = TransferAdmission(limit=1, max_waiting=0, wait_seconds=0.1)
        for _ in range(5):
            gate.release(await gate.acquire())
        assert gate.stats()["in_flight"] == 0
        await gate.acquire()          # still works after all that
    _run(_go())


def test_the_limit_is_never_exceeded_under_a_burst():
    """The property, checked by watching the peak rather than by reasoning about the mechanism."""
    async def _go():
        gate = TransferAdmission(limit=4, max_waiting=50, wait_seconds=10)
        peak = 0
        current = 0
        lock = asyncio.Lock()

        async def _transfer():
            nonlocal peak, current
            token = await gate.acquire()
            async with lock:
                current += 1
                peak = max(peak, current)
            await asyncio.sleep(0.01)
            async with lock:
                current -= 1
            gate.release(token)

        await asyncio.gather(*(_transfer() for _ in range(40)))
        assert peak <= 4, f"{peak} transfers ran at once against a limit of 4"
        assert gate.stats()["in_flight"] == 0
        assert gate.stats()["waiting"] == 0
    _run(_go())


def test_a_limit_below_one_is_treated_as_one():
    """A misconfiguration should throttle, not deadlock the deployment."""
    async def _go():
        gate = TransferAdmission(limit=0, max_waiting=0, wait_seconds=0.1)
        assert gate.limit == 1
        gate.release(await gate.acquire())
    _run(_go())


def test_the_configuration_is_reported():
    """An operator who cannot see the ceiling cannot size around it."""
    gate = TransferAdmission(limit=7, max_waiting=3, wait_seconds=15)
    stats = gate.stats()
    assert stats["limit"] == 7
    assert stats["max_waiting"] == 3
    assert stats["wait_seconds"] == 15


def test_the_counters_report_what_the_gate_actually_did():
    """An operator sizing against the ceiling needs the history, not just the configuration.

    "In flight" alone cannot distinguish a deployment that is comfortably below its ceiling from
    one that has been shedding load all afternoon and happens to be quiet when it is looked at.
    """
    gate = TransferAdmission(limit=2, max_waiting=0, wait_seconds=0.01)
    fresh = gate.stats()
    assert (fresh["admitted"], fresh["refused"], fresh["peak_in_flight"]) == (0, 0, 0)

    async def _go():
        first = await gate.acquire()
        second = await gate.acquire()
        at_capacity = gate.stats()
        assert at_capacity["admitted"] == 2
        assert at_capacity["peak_in_flight"] == 2
        assert at_capacity["in_flight"] == 2

        with pytest.raises(TransferBusy):
            await gate.acquire()
        assert gate.stats()["refused"] == 1

        gate.release(first)
        gate.release(second)
        emptied = gate.stats()
        assert emptied["in_flight"] == 0
        # The peak and the totals are history: they do not fall when the deployment quietens.
        assert emptied["peak_in_flight"] == 2
        assert emptied["admitted"] == 2
        assert emptied["refused"] == 1

        third = await gate.acquire()
        assert gate.stats()["admitted"] == 3, "a reused slot is still an admission"
        assert gate.stats()["peak_in_flight"] == 2, "one in flight is not a new peak"
        gate.release(third)
    _run(_go())


def test_a_release_nobody_made_cannot_raise_the_ceiling_or_the_counters():
    """A stray release must not hand out a slot, and must not look like a transfer.

    Both halves matter and only one of them is about the numbers: a release from something that
    never held a slot would raise the real ceiling above the configured one, which is the whole
    reason slots are tokens rather than a count. Checked by trying to exceed the ceiling
    afterwards, because asserting on the counters alone passes even when the ceiling has moved.
    """
    gate = TransferAdmission(limit=1, max_waiting=0, wait_seconds=0.01)

    async def _go():
        for stray in (object(), None, "not a token"):
            gate.release(stray)
        assert gate.stats()["admitted"] == 0, "a stray release counted as a transfer"
        assert gate.stats()["in_flight"] == 0

        held = await gate.acquire()
        gate.release(held)
        gate.release(held)                        # a second release of a real token
        assert gate.stats()["admitted"] == 1
        assert gate.stats()["in_flight"] == 0

        # The ceiling is still one. If any of the five releases above reached the semaphore, it is
        # now two or more and this second acquire succeeds.
        again = await gate.acquire()
        with pytest.raises(TransferBusy):
            await gate.acquire()
        gate.release(again)
    _run(_go())


@pytest.mark.parametrize("configured,expected", [
    (float("inf"), TransferAdmission.MAX_WAIT_SECONDS),
    (float("nan"), 0.0),
    (-5.0, 0.0),
    (20.0, 20.0),
    (7200.0, TransferAdmission.MAX_WAIT_SECONDS),
])
def test_an_unusable_wait_still_produces_an_answer_a_client_can_act_on(configured, expected):
    """A float setting accepts inf and nan, and both used to reach the refusal path intact.

    The refusal carries Retry-After, which is a whole number of seconds: an infinite wait made
    building it raise, so a full deployment answered 500 -- indistinguishable from a broken one --
    instead of "come back shortly". The counter had already moved by then, so the deployment also
    recorded shedding load it never told anyone about.
    """
    gate = TransferAdmission(limit=1, max_waiting=0, wait_seconds=configured)
    assert gate.stats()["wait_seconds"] == expected

    async def _go():
        held = await gate.acquire()
        try:
            with pytest.raises(TransferBusy) as refusal:
                await gate.acquire()
            assert isinstance(refusal.value.retry_after, int)
            assert refusal.value.retry_after >= 1
        finally:
            gate.release(held)
    _run(_go())
