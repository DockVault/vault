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
    }

    /** How many are running now. */
    get active() { return this._active; }

    /** How many are waiting for a slot. */
    get waiting() { return this._waiting.length; }

    /**
     * Wait for a slot. Resolves when one is free; the caller MUST release it.
     *
     * Prefer `run`, which cannot forget. This is here for a caller that has to hold a slot across
     * something it does not control.
     */
    acquire() {
        if (this._active < this.limit) {
            this._active += 1;
            return Promise.resolve();
        }
        return new Promise(resolve => this._waiting.push(resolve));
    }

    /**
     * Give a slot back, handing it directly to whoever has waited longest.
     *
     * First in, first out, so a queue of twenty finishes in the order it was dropped rather than
     * in whatever order the event loop happens to wake things. Releasing more times than you
     * acquired is ignored rather than allowed to drive the count negative -- which would quietly
     * raise the limit for everyone else.
     */
    release() {
        if (this._active === 0 && this._waiting.length === 0) return;
        const next = this._waiting.shift();
        if (next) {
            // The slot passes straight to the waiter: `_active` is not decremented, because the
            // count of running transfers has not changed. Decrementing and re-incrementing would
            // open a window where a third caller could take the slot out of turn.
            next();
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
        await this.acquire();
        try {
            return await task();
        } finally {
            this.release();
        }
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = TransferGate;
}
