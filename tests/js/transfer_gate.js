#!/usr/bin/env node
'use strict';

// A concurrency gate is four lines of intent and a great many ways to be wrong.
//
// The failure that matters is not "too many ran" -- that is loud. It is a slot never given back,
// which wedges the queue after exactly `limit` failures, with the symptom being uploads that
// simply never start and no error anywhere. So the throwing case is tested as carefully as the
// happy one, and the peak concurrency is measured rather than assumed.

const path = require('path');
const TransferGate = require(path.resolve(__dirname, '../../static/js/transfer_gate.js'));

let failures = 0;
const note = (ok, msg) => {
    if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.error('FAIL ' + msg); }
};

const tick = (ms = 0) => new Promise(r => setTimeout(r, ms));

async function main() {
    // Twenty tasks, five at a time. Peak concurrency is watched throughout rather than sampled.
    {
        const gate = new TransferGate(5);
        let running = 0, peak = 0, done = 0;
        await Promise.all(Array.from({ length: 20 }, (_, i) => gate.run(async () => {
            running += 1;
            peak = Math.max(peak, running);
            await tick(5 + (i % 3));
            running -= 1;
            done += 1;
        })));
        note(peak === 5, `twenty tasks peak at five at once (peak was ${peak})`);
        note(done === 20, `all twenty complete (${done})`);
        note(gate.active === 0 && gate.waiting === 0,
             `the gate is empty afterwards (active ${gate.active}, waiting ${gate.waiting})`);
    }

    // A task that throws must not cost a slot. Five throwing tasks against a limit of five is the
    // exact case that wedges a leaking gate forever.
    {
        const gate = new TransferGate(5);
        const attempts = Array.from({ length: 5 }, () =>
            gate.run(async () => { throw new Error('transfer failed'); }).catch(() => 'caught'));
        note((await Promise.all(attempts)).every(r => r === 'caught'), 'failures propagate');

        // Bounded, because a leaked slot does not make this fail -- it makes it HANG, and a hang
        // is an absence of an answer rather than a red test. Whoever ran it would wait for a
        // timeout somewhere else and go looking in the wrong place.
        let ran = false;
        const started = gate.run(async () => { ran = true; }).then(() => 'ran');
        const outcome = await Promise.race([started, tick(2000).then(() => 'never started')]);
        note(outcome === 'ran' && ran,
             `a sixth task still runs after five failures -- no slot was leaked (${outcome})`);
        note(gate.active === 0, `the gate is empty after failures (active ${gate.active})`);
    }

    // Uploads and downloads share ONE gate: two gates of five would be a cap of ten.
    {
        const gate = new TransferGate(5);
        let running = 0, peak = 0;
        const work = (n) => Array.from({ length: n }, () => gate.run(async () => {
            running += 1; peak = Math.max(peak, running);
            await tick(4);
            running -= 1;
        }));
        await Promise.all([...work(6), ...work(6)]);   // "uploads" and "downloads" together
        note(peak === 5, `mixed uploads and downloads still peak at five (peak was ${peak})`);
    }

    // First in, first out, so a dropped batch finishes roughly in the order it was dropped.
    {
        const gate = new TransferGate(1);
        const order = [];
        await Promise.all([1, 2, 3, 4].map(n => gate.run(async () => {
            order.push(n);
            await tick(2);
        })));
        note(order.join(',') === '1,2,3,4', `waiters are served in order (${order.join(',')})`);
    }

    // Releasing more than was acquired must not raise the limit for everyone else.
    {
        const gate = new TransferGate(2);
        gate.release(); gate.release(); gate.release();
        let running = 0, peak = 0;
        await Promise.all(Array.from({ length: 6 }, () => gate.run(async () => {
            running += 1; peak = Math.max(peak, running);
            await tick(3);
            running -= 1;
        })));
        note(peak === 2, `stray releases do not widen the gate (peak was ${peak})`);
    }

    // A reset (a sign-out on the page) frees every slot and drops every caller still waiting. Some of what the person
    // who signed out had running never ends (a transfer waiting for their account key never settles once they have
    // gone), so it never gives its slot back; what does end gives nothing back to the new gate; what was queued never
    // starts, since it would run with the next person's session.
    {
        const gate = new TransferGate(5);
        const held = () => { let let_go; const p = new Promise(r => { let_go = r; }); return { p, let_go }; };
        const forever = () => new Promise(() => {});
        const before = [held(), held()];
        let queuedStarted = 0;
        gate.run(forever); gate.run(forever); gate.run(forever);
        before.forEach(h => gate.run(() => h.p));
        for (let i = 0; i < 3; i++) gate.run(async () => { queuedStarted += 1; });
        await tick();
        note(gate.active === 5 && gate.waiting === 3,
             `the first person's five run and three wait (active ${gate.active}, waiting ${gate.waiting})`);

        gate.reset();
        note(gate.active === 0 && gate.waiting === 0,
             `a reset frees every slot (active ${gate.active}, waiting ${gate.waiting})`);

        let running = 0, peak = 0, started = 0;
        const next = Array.from({ length: 6 }, () => held());
        const runs = next.map(h => gate.run(async () => {
            started += 1; running += 1; peak = Math.max(peak, running);
            await h.p;
            running -= 1;
        }));
        await tick();
        note(started === 5 && gate.waiting === 1,
             `the next person's five start at once after a reset (${started}, waiting ${gate.waiting})`);

        before.forEach(h => h.let_go());     // two transfers from before the reset end now
        await tick();
        note(gate.active === 5 && started === 5,
             `transfers from before a reset that end give nothing back (active ${gate.active}, started ${started})`);

        next.forEach(h => h.let_go());
        await Promise.all(runs);
        await tick();
        note(started === 6 && peak === 5, `the next person's sixth runs once a slot is theirs (peak ${peak})`);
        note(queuedStarted === 0, `what was queued before a reset never starts (${queuedStarted})`);
        note(gate.active === 0 && gate.waiting === 0,
             `the gate empties afterwards (active ${gate.active}, waiting ${gate.waiting})`);
    }

    // A slot handed to a waiter before a reset belongs to the gate before it: given back after the reset, it is
    // ignored, so it cannot open a sixth place beside the next person's five.
    {
        const gate = new TransferGate(1);
        const first = await gate.acquire();
        const handed = gate.acquire();       // waits
        gate.release(first);                 // the slot passes to the waiter...
        gate.reset();                        // ...and the person signs out before it runs
        const epoch = await handed;
        const mine = await gate.acquire();   // the next person's
        gate.release(epoch);                 // the one from before ends
        let second = false;
        gate.acquire().then(() => { second = true; });
        await tick();
        note(!second && gate.active === 1 && gate.waiting === 1,
             `a slot handed over before a reset is not given back to the gate after it (active ${gate.active}, waiting ${gate.waiting})`);
        gate.release(mine);
        await tick();
        note(second, 'the next caller of the gate after a reset is served when its slot is given back');
    }

    // A limit that makes no sense is refused rather than silently treated as one.
    for (const bad of [0, -1, 1.5, NaN, '5', null, undefined]) {
        let threw = false;
        try { new TransferGate(bad); } catch (_) { threw = true; }
        // `undefined` is the documented default of five, so it is the one value that may pass.
        const expected = bad === undefined ? false : true;
        note(threw === expected, `a limit of ${String(bad)} is ${expected ? 'refused' : 'the default'}`);
    }

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('the gate bounds concurrency and never loses a slot');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
