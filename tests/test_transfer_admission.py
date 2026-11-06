"""How many transfers are carried at once, and what happens to the ones that arrive after.

Each transfer costs a bounded amount now, which is what makes a limit on their number meaningful.
Before this, nothing counted them: a hundred simultaneous downloads were all attempted.

The behaviour that matters is at the edges. A caller arriving at a full deployment must wait rather
than be dropped; a caller that waits too long must be told to come back rather than be handed
something that reads like a broken file; and the ceiling must be a real ceiling, including when
slots are released twice or released by something that never took one.
"""

import asyncio

from _async_run import run_coroutine  # the one loop helper; see tests/_async_run.py

import pytest

from app.core.transfer_admission import ShareBusy, TransferAdmission, TransferBusy


pytestmark = pytest.mark.unit


def test_transfers_up_to_the_limit_are_admitted_immediately():
    async def _go():
        gate = TransferAdmission(limit=3, max_waiting=5, wait_seconds=5)
        for _ in range(3):
            await gate.acquire()
        assert gate.stats()["in_flight"] == 3
    run_coroutine(_go())


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
    run_coroutine(_go())


def test_a_caller_that_waits_too_long_is_told_to_come_back():
    """Not dropped, and not disguised as a failure: a distinct outcome carrying an interval."""
    async def _go():
        gate = TransferAdmission(limit=1, max_waiting=4, wait_seconds=0.2)
        await gate.acquire()

        with pytest.raises(TransferBusy) as refused:
            await gate.acquire()

        assert refused.value.retry_after >= 1, "a refusal without an interval is not actionable"
        assert refused.value.limit == 1
    run_coroutine(_go())


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
    run_coroutine(_go())


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
    run_coroutine(_go())


def test_a_released_slot_is_reusable():
    async def _go():
        gate = TransferAdmission(limit=1, max_waiting=0, wait_seconds=0.1)
        for _ in range(5):
            gate.release(await gate.acquire())
        assert gate.stats()["in_flight"] == 0
        await gate.acquire()          # still works after all that
    run_coroutine(_go())


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
    run_coroutine(_go())


def test_a_limit_below_one_is_treated_as_one():
    """A misconfiguration should throttle, not deadlock the deployment."""
    async def _go():
        gate = TransferAdmission(limit=0, max_waiting=0, wait_seconds=0.1)
        assert gate.limit == 1
        gate.release(await gate.acquire())
    run_coroutine(_go())


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
    run_coroutine(_go())


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
    run_coroutine(_go())


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
    run_coroutine(_go())


def test_the_wait_ceiling_is_an_hour():
    """Pinned because the management tool mirrors this number rather than importing it."""
    assert TransferAdmission.MAX_WAIT_SECONDS == 3600.0


# ---- one holder's share ------------------------------------------------------------------------------------------
#
# A copy needs no slow client to last, and one account's folder copies of a large tree held every slot for minutes
# while everyone else waited, then was refused. With a holder (an account), at most `share` of the slots are held
# by that holder's acquires at once (copy_share: a quarter of the ceiling, at least one). One past its share waits in
# a room of the holder's own, so one account cannot fill the deployment's waiting room either, and a refusal past it
# says so (ShareBusy) and is not counted as load the deployment shed.

def test_a_copy_share_is_a_quarter_of_the_ceiling_and_at_least_one():
    from app.core.transfer_admission import copy_share
    assert [copy_share(n) for n in (-3, 0, 1, 3, 4, 7, 8, 16, 40)] == [1, 1, 1, 1, 1, 1, 2, 4, 10]


def test_one_holder_past_its_share_waits_while_another_is_admitted_at_once():
    async def _go():
        gate = TransferAdmission(limit=4, max_waiting=8, wait_seconds=5)
        mine = [await gate.acquire(holder="a", share=2) for _ in range(2)]
        third = asyncio.create_task(gate.acquire(holder="a", share=2))
        await asyncio.sleep(0.05)
        assert not third.done(), "a holder took more than its share"
        assert gate.stats()["waiting_for_share"] == 1 and gate.stats()["in_flight"] == 2
        assert gate.stats()["waiting"] == 0, "waiting for its share took a place in the deployment's waiting room"
        theirs = await asyncio.wait_for(gate.acquire(holder="b", share=2), timeout=1)
        anyone = await asyncio.wait_for(gate.acquire(), timeout=1)
        assert gate.stats()["in_flight"] == 4 and not third.done()
        gate.release(theirs)
        await asyncio.sleep(0.05)
        assert not third.done(), "another holder's slot let it past its share"
        gate.release(mine[0])
        token = await asyncio.wait_for(third, timeout=1)
        assert gate.stats()["in_flight"] == 3 and gate.stats()["waiting_for_share"] == 0
        for t in (mine[1], token, anyone):
            gate.release(t)
        assert gate.stats()["in_flight"] == 0 and gate._holders == {} and gate._holder_of == {}
    run_coroutine(_go())


def test_its_share_still_holds_once_one_of_its_transfers_ends_while_another_runs():
    """The holder's entry counts every acquire using it, so it outlives the end of any one of them while another
    still runs. Were it forgotten at the first release, the holder's next acquire would start a share of its own,
    and the holder would run past its share."""
    async def _go():
        gate = TransferAdmission(limit=4, max_waiting=8, wait_seconds=5)
        first = await gate.acquire(holder="a", share=2)
        second = await gate.acquire(holder="a", share=2)
        third = asyncio.create_task(gate.acquire(holder="a", share=2))
        await asyncio.sleep(0.05)
        assert not third.done(), "a holder took more than its share"
        gate.release(first)
        third_token = await asyncio.wait_for(third, timeout=1)
        # Two of its transfers run (the second and the third): one more waits for one of them to end.
        fourth = asyncio.create_task(gate.acquire(holder="a", share=2))
        await asyncio.sleep(0.05)
        assert not fourth.done(), "once one of its transfers ended, the holder ran past its share"
        assert gate.stats()["in_flight"] == 2 and gate.stats()["waiting_for_share"] == 1
        gate.release(second)
        fourth_token = await asyncio.wait_for(fourth, timeout=1)
        for t in (third_token, fourth_token):
            gate.release(t)
        assert gate.stats()["in_flight"] == 0 and gate._holders == {} and gate._holder_of == {}
    run_coroutine(_go())


def test_a_holder_past_its_share_for_the_whole_wait_is_told_its_share_is_in_use():
    """Told that its own share is in use, not that the deployment is full (it is not), and not counted as load the
    deployment shed: an operator sizes the ceiling by that count."""
    async def _go():
        gate = TransferAdmission(limit=4, max_waiting=8, wait_seconds=0.2)
        held = await gate.acquire(holder="a", share=1)
        with pytest.raises(ShareBusy) as refusal:
            await gate.acquire(holder="a", share=1)
        assert refusal.value.share == 1 and refusal.value.retry_after >= 1
        assert isinstance(refusal.value, TransferBusy), "every caller that answers a refusal still answers this one"
        stats = gate.stats()
        assert (stats["in_flight"], stats["waiting"], stats["waiting_for_share"]) == (1, 0, 0)
        assert (stats["refused"], stats["refused_over_share"]) == (0, 1)
        gate.release(held)
        assert gate._holders == {}, "the refused acquire left its share taken"
        gate.release(await asyncio.wait_for(gate.acquire(holder="a", share=1), timeout=1))
    run_coroutine(_go())


def test_waiting_for_its_share_is_bounded_by_a_room_of_its_own():
    """As large as the deployment's: with no room to wait, one past its share is refused at once, as its share."""
    async def _go():
        gate = TransferAdmission(limit=4, max_waiting=0, wait_seconds=5)
        held = await gate.acquire(holder="a", share=1)
        with pytest.raises(ShareBusy):
            await gate.acquire(holder="a", share=1)
        stats = gate.stats()
        assert (stats["refused"], stats["refused_over_share"], stats["in_flight"]) == (0, 1, 1)
        gate.release(held)
        assert gate._holders == {}
    run_coroutine(_go())


def test_one_holder_filling_its_own_room_leaves_the_deployments_room_to_everyone_else():
    """One account sends more copies than its share and its room hold. Those past its share wait in its own room;
    the deployment's room stays free, so once the ceiling is full another caller waits for a slot rather than being
    refused at once. With one room for both, the account's copies filled it, and everyone else was refused at once
    while they waited."""
    async def _go():
        gate = TransferAdmission(limit=3, max_waiting=2, wait_seconds=5)
        mine = await gate.acquire(holder="a", share=1)
        waiting = [asyncio.create_task(gate.acquire(holder="a", share=1)) for _ in range(2)]
        await asyncio.sleep(0.05)
        with pytest.raises(ShareBusy):
            await gate.acquire(holder="a", share=1)
        assert gate.stats()["waiting_for_share"] == 2 and gate.stats()["waiting"] == 0
        others = [await asyncio.wait_for(gate.acquire(), timeout=1) for _ in range(2)]
        assert gate.stats()["in_flight"] == 3
        late = asyncio.create_task(gate.acquire())
        await asyncio.sleep(0.05)
        assert not late.done(), "another caller was refused at once: the account's copies filled its room"
        assert gate.stats()["waiting"] == 1 and gate.stats()["refused"] == 0
        gate.release(others[0])
        gate.release(await asyncio.wait_for(late, timeout=1))
        gate.release(mine)
        gate.release(await asyncio.wait_for(waiting[0], timeout=1))
        gate.release(await asyncio.wait_for(waiting[1], timeout=1))
        gate.release(others[1])
        stats = gate.stats()
        assert (stats["in_flight"], stats["waiting"], stats["waiting_for_share"]) == (0, 0, 0)
        assert gate._holders == {} and gate._holder_of == {}
    run_coroutine(_go())


def test_the_wait_for_its_share_and_for_a_slot_is_one_wait():
    """Its share frees after most of the wait, and the slot that freed is taken by someone else first: the rest of
    the one wait runs out, rather than a second whole wait for a slot."""
    async def _go():
        gate = TransferAdmission(limit=2, max_waiting=8, wait_seconds=1.0)
        loop = asyncio.get_running_loop()
        blocker = await gate.acquire()
        mine = await gate.acquire(holder="a", share=1)
        started = loop.time()
        late = asyncio.create_task(gate.acquire(holder="a", share=1))
        await asyncio.sleep(0.6)
        gate.release(mine)
        second_blocker = await gate.acquire()     # takes the slot `mine` freed before `late` runs again
        with pytest.raises(TransferBusy):
            await late
        took = loop.time() - started
        assert 0.9 < took < 1.3, f"{took:.2f} s: it waited for its share and then a whole wait again for a slot"
        gate.release(blocker)
        gate.release(second_blocker)
        assert gate._holders == {} and gate.stats()["in_flight"] == 0
    run_coroutine(_go())


@pytest.mark.parametrize("while_waiting_for", ["its share", "a slot"])
def test_a_holder_that_stops_waiting_gives_everything_back(while_waiting_for):
    async def _go():
        gate = TransferAdmission(limit=2, max_waiting=8, wait_seconds=5)
        if while_waiting_for == "its share":
            held = [await gate.acquire(holder="a", share=1)]
        else:
            held = [await gate.acquire(), await gate.acquire()]
        task = asyncio.create_task(gate.acquire(holder="a", share=1))
        await asyncio.sleep(0.05)
        room = "waiting_for_share" if while_waiting_for == "its share" else "waiting"
        assert gate.stats()[room] == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert gate.stats()["waiting"] == 0 and gate.stats()["waiting_for_share"] == 0
        for t in held:
            gate.release(t)
        assert gate._holders == {} and gate.stats()["in_flight"] == 0
        # Nothing of the one that stopped waiting is still taken: the whole ceiling, and each share, is usable.
        tokens = [await asyncio.wait_for(gate.acquire(holder=h, share=1), timeout=1) for h in ("a", "b")]
        for t in tokens:
            gate.release(t)
    run_coroutine(_go())


def test_a_holder_that_stops_waiting_for_a_slot_gives_its_share_back_while_its_other_transfers_run():
    """It had its share and was waiting for a slot. Its account's share is still in use by its other transfer, so
    what it took of the share must be back: the account's next copy is admitted at once once a slot is free."""
    async def _go():
        gate = TransferAdmission(limit=2, max_waiting=8, wait_seconds=5)
        first = await gate.acquire(holder="a", share=2)
        other = await gate.acquire()
        task = asyncio.create_task(gate.acquire(holder="a", share=2))
        await asyncio.sleep(0.05)
        assert gate.stats()["waiting"] == 1, "it is not waiting for a slot"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        gate.release(other)
        second = await asyncio.wait_for(gate.acquire(holder="a", share=2), timeout=1)
        assert gate.stats()["in_flight"] == 2
        for t in (first, second):
            gate.release(t)
        assert gate._holders == {}
    run_coroutine(_go())
