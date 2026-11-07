/**
 * How many transfers this browser runs at once.
 *
 * The server already caps what a deployment will accept. This is a different cap for a different
 * victim: the page starts every queued item the moment it is queued, so dropping twenty files on
 * it opens twenty uploads in one tab. The deployment refuses the excess and is fine; the browser
 * has already paid for twenty concurrent encryptions and twenty sets of buffers.
 *
 * Uploads and downloads share one gate deliberately. Two gates of five would be a cap of ten, and
 * a user who starts downloads while uploads are running is exactly the case worth bounding.
 *
 * Pure and dependency-free so it can be tested off the browser: concurrency limits are easy to
 * write and easy to get subtly wrong, and the interesting cases -- a task that throws, a caller
 * that never releases, order under contention -- are all reachable without a page.
 */
'use strict';

class TransferGate {
    /**
     * @param {number} limit how many may run at once. Five is the owner's figure.
     */
    constructor(limit = 5) {
        if (!Number.isSafeInteger(limit) || limit < 1) {
            throw new RangeError('a transfer gate needs a limit of at least one');
        }
        this.limit = limit;
        this._active = 0;
        this._waiting = [];
        // Which gate this is since the last reset: a slot is given out for one, and given back only to it.
        this._epoch = 0;
    }

    /** How many are running now. */
    get active() { return this._active; }

    /** How many are waiting for a slot. */
    get waiting() { return this._waiting.length; }

    /**
     * Wait for a slot. Resolves when one is free; the caller MUST release it.
     *
     * Prefer `run`, which cannot forget. This is here for a caller that has to hold a slot across
     * something it does not control. It resolves to the gate the slot was given out for (see
     * `reset`), which `release` takes back.
     */
    acquire() {
        if (this._active < this.limit) {
            this._active += 1;
            return Promise.resolve(this._epoch);
        }
        return new Promise(resolve => this._waiting.push(resolve));
    }

    /**
     * Give a slot back, handing it directly to whoever has waited longest.
     *
     * First in, first out, so a queue of twenty finishes in the order it was dropped rather than
     * in whatever order the event loop happens to wake things. Releasing more times than you
     * acquired is ignored rather than allowed to drive the count negative -- which would quietly
     * raise the limit for everyone else. So is a slot given out before a reset (`epoch`, what
     * `acquire` resolved to): the gate it was taken from is gone, and giving it back to this one
     * would let a sixth transfer run beside the five it now counts.
     */
    release(epoch = this._epoch) {
        if (epoch !== this._epoch) return;
        if (this._active === 0 && this._waiting.length === 0) return;
        const next = this._waiting.shift();
        if (next) {
            // The slot passes straight to the waiter: `_active` is not decremented, because the
            // count of running transfers has not changed. Decrementing and re-incrementing would
            // open a window where a third caller could take the slot out of turn.
            next(this._epoch);
            return;
        }
        this._active -= 1;
    }

    /**
     * Run `task` inside a slot, releasing it however the task ends.
     *
     * The release is in a `finally` because a failed transfer must not cost a slot permanently:
     * five failures would otherwise wedge the queue for the life of the page, and the symptom --
     * uploads that never start, with no error -- points nowhere near the cause.
     */
    async run(task) {
        const epoch = await this.acquire();
        try {
            return await task();
        } finally {
            this.release(epoch);
        }
    }

    /**
     * Start again with every slot free and nobody waiting, as a sign-out does on the page.
     *
     * What the person who signed out had running belongs to them, and some of it never ends: a
     * transfer waiting for their account key to be unlocked stops, unsettled, when they sign out,
     * so it never comes back to give its slot back, and five of them would leave the next person
     * on the tab a gate in which nothing ever starts. Every slot given out before is forgotten
     * (one of those transfers that does end gives nothing back to this gate), and every caller
     * still waiting is dropped without being started: its transfer would otherwise begin with the
     * next person's session.
     */
    reset() {
        this._epoch += 1;
        this._active = 0;
        this._waiting = [];
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = TransferGate;
}
