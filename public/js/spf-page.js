// The SPF page. Links can prefill the form, e.g. /spf?ip=1.2.3.4&email=info@example.com,
// and checks run here in the browser, so email addresses never leave it.

import { check, parseIp } from './spf.js';

const form = document.querySelector('form');
const button = form.querySelector('[type=submit]');
const message = document.querySelector('#message');

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
        const { status, reason, domain, records, suggestion } = await check(ip, email);
        const template = status === 'PASS' ? 'pass' : status === 'NONE' ? 'none' : 'problem';
        show(template, {
            ip,
            domain,
            status,
            reason,
            records,
            recordCount: records.length,
            multipleRecords: records.length > 1,
            suggestion,
        });
    } catch (error) {
        console.error(error);
        show('error');
    } finally {
        button.disabled = false;
    }
});

/** Show a message from its template, filling in the values */
function show(id, values = {}) {
    const content = document.getElementById(id).content.cloneNode(true);

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

    message.replaceChildren(content);
}
