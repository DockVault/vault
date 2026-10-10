/*
 * The Activity page's notes on archived days (app/services/activity_archive.py).
 *
 * The audit log keeps days older than its row window as compressed daily blocks. The Events list reads them when
 * its time range starts on or before an archived day (at most a number of days at a time), and says so; a range
 * with no start reads rows only, and the note says where the archive is and how to search it. The summary band
 * counts archived hours from the blocks' summaries where they answer the filters; the note says which panels count
 * rows only. A day that could not be read is named.
 *
 * activity.js dispatches `activity:list` (the Events list's response, or null after an error) and `activity:band`
 * (the band's). Builds the notes with textContent only.
 */
(function () {
    'use strict';

    const BLOCKS = {
        events: 'the chart',
        categories: 'the categories',
        sign_ins: 'the sign-ins',
        people: 'the most active people',
        addresses: 'the most active addresses',
    };

    function list(words) {
        if (words.length <= 1) return words.join('');
        return words.slice(0, -1).join(', ') + ' and ' + words[words.length - 1];
    }

    function unreadable(items) {
        return items.map((u) => (typeof u === 'string' ? u : `${u.day} (${u.reason})`)).join(', ');
    }

    // What the Events list says of the archive: [text, whether it warns], or null for nothing to say.
    function listText(note) {
        if (!note) return null;
        if (!note.searched) {
            return [`Days up to ${note.newest_day} are archived and not in this list. To search them, choose a time ` +
                `range that starts on or before ${note.newest_day}: at most ${note.max_days} archived days at a time.`,
                false];
        }
        const days = note.searched_days === 1 ? '1 archived day' : `${note.searched_days} archived days`;
        let text = `This list includes ${days}, read from the archive.`;
        const gone = note.unreadable || [];
        if (gone.length) {
            text += ` These archived days could not be read, so their events are not in it: ${unreadable(gone)}.` +
                ' The server\'s operator can check them with dockvault.py audit verify.';
        }
        return [text, gone.length > 0];
    }

    // What the summary band says of the archive: [text, whether it warns], or null.
    function bandText(note) {
        if (!note) return null;
        const counted = (note.counted || []).map((b) => BLOCKS[b] || b);
        const rowsOnly = (note.rows_only || []).map((b) => BLOCKS[b] || b);
        let text;
        if (!counted.length) {
            text = `Days up to ${note.newest_day} are archived, and these filters need the events themselves, so the ` +
                'summary counts the days still kept as rows only. Search the archived days in the list, with a time range.';
        } else {
            text = `Days up to ${note.newest_day} are archived: ${list(counted)} count them from the archive's ` +
                `summaries; ${list(rowsOnly)} count the days still kept as rows only.`;
        }
        const gone = note.unreadable || [];
        if (gone.length) text += ` Archived days whose summaries could not be read are not counted: ${unreadable(gone)}.`;
        return [text, gone.length > 0];
    }

    function show(id, said) {
        const box = document.getElementById(id);
        if (!box) return;
        if (!said) {
            box.textContent = '';
            box.hidden = true;
            return;
        }
        box.textContent = said[0];
        box.classList.toggle('text-warning', said[1]);
        box.classList.toggle('text-secondary', !said[1]);
        box.hidden = false;
    }

    document.addEventListener('activity:list', (e) => show('act-archive-list', listText(e.detail && e.detail.archive)));
    document.addEventListener('activity:band', (e) => show('act-archive-band', bandText(e.detail && e.detail.archive)));

    window.ActivityArchive = { listText, bandText };
})();
