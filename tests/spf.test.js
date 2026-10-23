import { test } from 'node:test';
import assert from 'node:assert/strict';

import { DnsError, txtData } from '../public/js/dns.js';
import { check, expand, parseIp, withIp } from '../public/js/spf.js';

/** A resolver answering from `zone`, e.g. { 'example.com': { TXT: ['v=spf1 -all'] } } */
function fakeDns(zone) {
    return async (name, type) => {
        const records = zone[name]?.[type] ?? [];
        if (records === 'SERVFAIL') {
            throw new DnsError(`${type} lookup for ${name} failed`);
        }
        return records;
    };
}

/** The status for checking `ip` against example.com, with these records */
async function status(ip, zone) {
    const result = await check(ip, 'someone@example.com', fakeDns(zone));
    return result.status;
}

const spf = record => ({ TXT: [record] });

test('ip4 and ip6 mechanisms match IPs in their networks', async () => {
    const zone = { 'example.com': spf('v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all') };

    assert.equal(await status('192.0.2.200', zone), 'PASS');
    assert.equal(await status('192.0.3.1', zone), 'FAIL');
    assert.equal(await status('2001:db8:1::5', zone), 'PASS');
    assert.equal(await status('2001:db9::5', zone), 'FAIL');
    // IPv4-mapped IPv6 addresses are checked as IPv4
    assert.equal(await status('::ffff:192.0.2.1', zone), 'PASS');
});

test('qualifiers give their results, and no match is neutral', async () => {
    assert.equal(await status('192.0.2.1', { 'example.com': spf('v=spf1 ~all') }), 'SOFTFAIL');
    assert.equal(await status('192.0.2.1', { 'example.com': spf('v=spf1 ?all') }), 'NEUTRAL');
    assert.equal(await status('192.0.2.1', { 'example.com': spf('v=spf1 +all') }), 'PASS');
    assert.equal(await status('192.0.2.1', { 'example.com': spf('v=spf1 ip4:192.0.2.9') }), 'NEUTRAL');
    assert.equal(await status('192.0.2.1', { 'example.com': spf('V=SPF1 -IP4:192.0.2.1 +all') }), 'FAIL');
});

test('a and mx look up addresses, with optional prefixes', async () => {
    const zone = {
        'example.com': {
            ...spf('v=spf1 a mx:mail.example.com/24//64 -all'),
            A: ['192.0.2.1'],
        },
        'mail.example.com': { MX: ['mx1.example.com', 'mx2.example.com'] },
        'mx2.example.com': { A: ['198.51.100.1'], AAAA: ['2001:db8::1'] },
    };

    assert.equal(await status('192.0.2.1', zone), 'PASS');
    assert.equal(await status('192.0.2.2', zone), 'FAIL');
    assert.equal(await status('198.51.100.77', zone), 'PASS');
    assert.equal(await status('2001:db8::abcd', zone), 'PASS');
    assert.equal(await status('2001:db8:0:1::1', zone), 'FAIL');
});

test('includes match when they pass', async () => {
    const zone = {
        'example.com': spf('v=spf1 include:_spf.example.net -all'),
        '_spf.example.net': spf('v=spf1 ip4:192.0.2.0/24 ~all'),
    };

    assert.equal(await status('192.0.2.1', zone), 'PASS');
    // the include's ~all doesn't match, so the -all applies
    assert.equal(await status('198.51.100.1', zone), 'FAIL');
});

test('including a domain without SPF is a permerror', async () => {
    const zone = { 'example.com': spf('v=spf1 include:example.net -all') };
    assert.equal(await status('192.0.2.1', zone), 'PERMERROR');
});

test('redirects use the other domain\'s record when nothing matches', async () => {
    const zone = {
        'example.com': spf('v=spf1 ip4:192.0.2.1 redirect=_spf.example.net'),
        '_spf.example.net': spf('v=spf1 ip4:198.51.100.0/24 -all'),
    };

    assert.equal(await status('192.0.2.1', zone), 'PASS');
    assert.equal(await status('198.51.100.1', zone), 'PASS');
    assert.equal(await status('203.0.113.1', zone), 'FAIL');
    assert.equal(await status('192.0.2.1', { 'example.com': spf('v=spf1 redirect=nope.example') }), 'PERMERROR');
});

test('exists expands macros and looks for an A record', async () => {
    const zone = {
        'example.com': spf('v=spf1 exists:%{ir}.%{l1r-}.allowed.%{d} -all'),
        '1.2.0.192.someone.allowed.example.com': { A: ['127.0.0.2'] },
    };

    assert.equal(await status('192.0.2.1', zone), 'PASS');
    assert.equal(await status('192.0.2.2', zone), 'FAIL');
});

test('ptr matches validated host names in the domain', async () => {
    const zone = {
        'example.com': spf('v=spf1 ptr -all'),
        '1.2.0.192.in-addr.arpa': { PTR: ['mail.example.com'] },
        'mail.example.com': { A: ['192.0.2.1'] },
        // points at example.com, but example.com doesn't point back
        '2.2.0.192.in-addr.arpa': { PTR: ['fake.example.com'] },
    };

    assert.equal(await status('192.0.2.1', zone), 'PASS');
    assert.equal(await status('192.0.2.2', zone), 'FAIL');
});

test('no SPF record is none', async () => {
    assert.equal(await status('192.0.2.1', {}), 'NONE');
    assert.equal(await status('192.0.2.1', { 'example.com': { TXT: ['google-site-verification=abc'] } }), 'NONE');

    const result = await check('192.0.2.1', 'someone@not a domain', fakeDns({}));
    assert.equal(result.status, 'NONE');
});

test('more than one SPF record is a permerror', async () => {
    const zone = { 'example.com': { TXT: ['v=spf1 -all', 'v=spf1 ~all'] } };
    const result = await check('192.0.2.1', 'someone@example.com', fakeDns(zone));

    assert.equal(result.status, 'PERMERROR');
    assert.deepEqual(result.records, ['v=spf1 -all', 'v=spf1 ~all']);
    assert.equal(result.suggestion, null);
});

test('DNS failures are temperrors', async () => {
    assert.equal(await status('192.0.2.1', { 'example.com': { TXT: 'SERVFAIL' } }), 'TEMPERROR');

    const zone = { 'example.com': spf('v=spf1 a:broken.example.com -all'), 'broken.example.com': { A: 'SERVFAIL' } };
    assert.equal(await status('192.0.2.1', zone), 'TEMPERROR');
});

test('invalid mechanisms are permerrors', async () => {
    const invalid = [
        'v=spf1 foo:bar -all',
        'v=spf1 ip4:nope -all',
        'v=spf1 ip6:192.0.2.1 -all',
        'v=spf1 include -all',
        'v=spf1 all:example.com',
        'v=spf1 ip4:192.0.2.0/33 -all',
        'v=spf1 ip4:192.0.2.0/abc -all',
        'v=spf1 ip6:2001:db8::/129 -all',
        // unknown mechanisms, even after a match
        'v=spf1 ip4:192.0.2.1 foo:bar',
    ];
    for (const record of invalid) {
        assert.equal(await status('192.0.2.1', { 'example.com': spf(record) }), 'PERMERROR', record);
    }
    // unknown modifiers are fine though
    assert.equal(await status('192.0.2.1', { 'example.com': spf('v=spf1 foo=bar ip4:192.0.2.1 -all') }), 'PASS');
});

test('more than 10 lookups is a permerror', async () => {
    const zone = { 'example.com': spf('v=spf1 include:a0.example.com -all') };
    for (let i = 0; i < 11; i++) {
        zone[`a${i}.example.com`] = spf(`v=spf1 include:a${i + 1}.example.com`);
    }
    zone['a11.example.com'] = spf('v=spf1 +all');

    assert.equal(await status('192.0.2.1', zone), 'PERMERROR');
});

test('errors say why', async () => {
    const reason = async zone => (await check('192.0.2.1', 'someone@example.com', fakeDns(zone))).reason;

    const tooMany = { 'example.com': spf('v=spf1 include:a0.example.com -all') };
    for (let i = 0; i < 11; i++) {
        tooMany[`a${i}.example.com`] = spf(`v=spf1 include:a${i + 1}.example.com`);
    }
    assert.match(await reason(tooMany), /more than 10 DNS lookups/);
    assert.equal(await reason({ 'example.com': spf('v=spf1 foo:bar -all') }), '"foo:bar" isn\'t valid in an SPF record.');
    assert.equal(await reason({ 'example.com': spf('v=spf1 -ip4:nope') }), '"ip4:nope" isn\'t valid in an SPF record.');
    assert.equal(await reason({ 'example.com': spf('v=spf1 include:Nope.example -all') }), 'It includes nope.example, which has no SPF record.');
    assert.equal(await reason({ 'example.com': spf('v=spf1 redirect=nope.example') }), 'It redirects to nope.example, which has no SPF record.');
    assert.match(await reason({ 'example.com': { TXT: 'SERVFAIL' } }), /Looking up example.com's TXT records failed/);
    const manyMx = { 'example.com': { ...spf('v=spf1 mx -all'), MX: Array.from({ length: 11 }, (_, i) => `mx${i}.example.com`) } };
    assert.equal(await reason(manyMx), 'example.com has more than 10 MX records, which is SPF\'s limit for mx.');
    assert.equal(await reason({ 'example.com': spf('v=spf1 -all') }), null);
});

test('the records are shown, with a suggestion when adding the IP would fix it', async () => {
    const zone = { 'example.com': spf('v=spf1 include:_spf.example.net ~all'), '_spf.example.net': spf('v=spf1 -all') };
    const result = await check('192.0.2.1', 'someone@Example.com', fakeDns(zone));

    assert.deepEqual(result, {
        status: 'SOFTFAIL',
        reason: null,
        domain: 'example.com',
        records: ['v=spf1 include:_spf.example.net ~all'],
        suggestion: 'v=spf1 ip4:192.0.2.1 include:_spf.example.net ~all',
    });
});

test('suggestions add the IP whatever the case of the record', () => {
    assert.equal(withIp('V=SPF1 -all', parseIp('1.2.3.4')), 'v=spf1 ip4:1.2.3.4 -all');
    assert.equal(withIp('v=spf1', parseIp('2001:0db8:0:0::0001')), 'v=spf1 ip6:2001:db8::1');
});

test('macros expand as in RFC 7208\'s examples', () => {
    const state = { ip: parseIp('192.0.2.3'), local: 'strong-bad', domain: 'email.example.com' };
    const examples = {
        '%{s}': 'strong-bad@email.example.com',
        '%{o}': 'email.example.com',
        '%{d}': 'email.example.com',
        '%{d4}': 'email.example.com',
        '%{d3}': 'email.example.com',
        '%{d2}': 'example.com',
        '%{d1}': 'com',
        '%{dr}': 'com.example.email',
        '%{d2r}': 'example.email',
        '%{l}': 'strong-bad',
        '%{l-}': 'strong.bad',
        '%{lr}': 'strong-bad',
        '%{lr-}': 'bad.strong',
        '%{l1r-}': 'strong',
        '%{ir}.%{v}._spf.%{d2}': '3.2.0.192.in-addr._spf.example.com',
        '%{lr-}.lp._spf.%{d2}': 'bad.strong.lp._spf.example.com',
        '%{lr-}.lp.%{ir}.%{v}._spf.%{d2}': 'bad.strong.lp.3.2.0.192.in-addr._spf.example.com',
        '%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}': '3.2.0.192.in-addr.strong.lp._spf.example.com',
        '%{d2}.trusted-domains.example.net': 'example.com.trusted-domains.example.net',
        '%%%_%-': '% %20',
    };
    for (const [spec, expanded] of Object.entries(examples)) {
        assert.equal(expand(state, spec, 'email.example.com'), expanded, spec);
    }

    const ipv6 = { ...state, ip: parseIp('2001:db8::cb01') };
    assert.equal(
        expand(ipv6, '%{ir}.%{v}._spf.%{d2}', 'email.example.com'),
        '1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com',
    );
});

test('IPs are parsed, and written in their usual form', () => {
    for (const ip of ['1.2.3.4', '0.0.0.0', '2001:db8::1', '::', '::1', '1::', 'fe80::1:2', '1:0:0:2::3']) {
        assert.equal(parseIp(ip).text, ip);
    }
    assert.equal(parseIp('2001:0DB8:0000:0000:0000:0000:0000:0001').text, '2001:db8::1');
    assert.equal(parseIp('1:0:0:2:0:0:3:4').text, '1::2:0:0:3:4');
    assert.deepEqual(parseIp('::ffff:1.2.3.4'), { version: 4, bytes: [1, 2, 3, 4], text: '1.2.3.4' });

    for (const notIp of ['', 'nope', '1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', '1:2:3', '1::2::3', '12345::', ':1::', '"><script>', '1::]@example.com']) {
        assert.equal(parseIp(notIp), null, notIp);
    }
});

test('TXT data is unquoted and joined', () => {
    assert.equal(txtData('"v=spf1 ip4:1.2.3.4 " "-all"'), 'v=spf1 ip4:1.2.3.4 -all');
    assert.equal(txtData('"say \\"hi\\"\\059 ok"'), 'say "hi"; ok');
    assert.equal(txtData('v=spf1 -all'), 'v=spf1 -all');
});
