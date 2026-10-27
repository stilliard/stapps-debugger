// The SPF page. Links can prefill the form, e.g. /spf?ip=1.2.3.4&email=info@example.com,
// and checks run here in the browser, so email addresses aren't sent to us.

import './shortcut.js';
import { check, parseIp, MAX_LOOKUPS } from './spf.js';

const form = document.querySelector('form');
const button = form.querySelector('[type=submit]');
const result = document.querySelector('#result');

const params = new URLSearchParams(location.search);
form.ip.value = params.get('ip')?.trim() ?? '';
form.email.value = params.get('email')?.trim() ?? '';

form.addEventListener('submit', async event => {
    event.preventDefault();
    const ip = form.ip.value.trim();
    const email = form.email.value.trim();

    if (!parseIp(ip)) {
        show('invalid-ip', { ip });
        return;
    }

    show('checking');
    button.disabled = true;
    try {
        const started = performance.now();
        const { status, reason, domain, records, suggestion, lookups, trace } = await check(ip, email);
        const card = show('report', {
            ip,
            domain,
            status,
            [status.toLowerCase()]: true,
            reason,
            records,
            recordCount: records.length,
            multipleRecords: records.length > 1,
            suggestion,
            // the count and time only mean something once there's a record to check
            lookups: records.length > 0 && String(lookups),
            maxLookups: MAX_LOOKUPS,
            time: Math.round(performance.now() - started),
            trace,
            mayNotSend: ['PERMERROR', 'TEMPERROR'].includes(status),
            problem: reason || ['PERMERROR', 'TEMPERROR'].includes(status),
        });
        card.dataset.status = status;

        const rows = card.querySelector('.trace');
        trace.forEach(({ term, detail, outcome }, i) => {
            const row = fill(document.getElementById('trace-row').content.cloneNode(true), {
                step: String(i + 1).padStart(2, '0'),
                term,
                detail,
                outcome,
            });
            row.querySelector('.outcome').dataset.outcome = outcome;
            rows?.append(row);
        });
    } catch (error) {
        console.error(error);
        show('error');
    } finally {
        button.disabled = false;
    }
});

/** Show a result from its template, filling in the values, and give its element */
function show(id, values = {}) {
    const content = fill(document.getElementById(id).content.cloneNode(true), values);
    const card = content.firstElementChild;
    result.replaceChildren(content);
    return card;
}

/** Fill in a template's fields, leaving out the parts with nothing for them */
function fill(content, values) {
    for (const part of content.querySelectorAll('[data-if]')) {
        const value = values[part.dataset.if];
        if (!value || value.length === 0) {
            part.remove();
        }
    }
    for (const field of content.querySelectorAll('[data-field]')) {
        const value = values[field.dataset.field];
        // lists go on separate lines
        field.replaceChildren(...[value].flat().flatMap((line, i) =>
            i === 0 ? [String(line)] : [document.createElement('br'), String(line)]));
    }
    return content;
}
