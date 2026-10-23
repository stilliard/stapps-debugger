// Checks real domains' SPF results, so needs internet access: `make test-dns`

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check } from '../public/js/spf.js';

test('real domains give the same results as the old PHP and Rust versions', async () => {
    const expected = [
        ['gmail.com', '209.85.220.41', 'PASS'],
        ['gmail.com', '1.2.3.4', 'SOFTFAIL'],
        ['gmail.com', '2607:f8b0:4864:20::1', 'PASS'],
        ['missionresources.co.uk', '5.153.230.21', 'FAIL'],
        ['example.com', '1.2.3.4', 'FAIL'],
        ['no-spf-here-zz91x.com', '1.2.3.4', 'NONE'],
        ['outlook.com', '40.92.0.1', 'PASS'],
        ['github.com', '192.30.252.1', 'PASS'],
        ['salesforce.com', '1.2.3.4', 'SOFTFAIL'],
        ['mailgun.org', '1.2.3.4', 'FAIL'],
        ['amazon.com', '1.2.3.4', 'FAIL'],
        ['stapps.io', '1.2.3.4', 'SOFTFAIL'],
        ['skirtech.co.uk', '40.92.0.1', 'PASS'],
        ['skirtech.co.uk', '1.2.3.4', 'SOFTFAIL'],
        ['wildfireinternet.co.uk', '209.85.220.41', 'PASS'],
        ['wildfireinternet.co.uk', '1.2.3.4', 'SOFTFAIL'],
        ['forgemotorsport.co.uk', '40.92.0.1', 'PASS'],
        ['forgemotorsport.co.uk', '1.2.3.4', 'FAIL'],
        ['brilliantwallart.co.uk', '79.170.40.114', 'PASS'],
        ['brilliantwallart.co.uk', '1.2.3.4', 'SOFTFAIL'],
        // its record needs 12 lookups, over SPF's limit of 10, unless the IP matches early on
        ['recplus.co.uk', '40.92.0.1', 'PASS'],
        ['recplus.co.uk', '1.2.3.4', 'PERMERROR'],
    ];

    for (const [domain, ip, status] of expected) {
        const result = await check(ip, `test@${domain}`);
        assert.equal(result.status, status, `${domain} ${ip}`);
    }
});
