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
