// Checking if an IP may send email for a domain, following SPF's rules
// (https://www.rfc-editor.org/rfc/rfc7208). It covers everything real records
// use, but skips some of the RFC's stricter checks on broken records.

import { resolve as dohResolve, DnsError } from './dns.js';

// SPF allows 10 lookups per check (include, a, mx, ptr, exists and redirect,
// all together), the limit busy records most often go over
const MAX_LOOKUPS = 10;
// and 10 MX names per mx (any more is a permerror), or PTR names per ptr (the
// rest are ignored)
const MAX_NAMES = 10;

const QUALIFIERS = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

// e.g. %{d}, %{ir} or %{l1r-}, and %%, %_ and %- for "%", " " and "%20"
const MACRO = /%(?:\{([slodipvh])(\d*)(r?)([-.+,/_=]*)\}|[%_-])/gi;

/** Ends the check early with a result, e.g. permerror for a broken record, and why */
class Stop extends Error {
    constructor(result, reason = null) {
        super(reason ?? result);
        this.result = result;
        this.reason = reason;
    }
}

const invalid = term => new Stop('permerror', `"${term}" isn't valid in an SPF record.`);

/**
 * Check if `ip` may send email from `email`, giving the result (PASS, FAIL,
 * SOFTFAIL, NEUTRAL, NONE, TEMPERROR or PERMERROR), why for errors, the email's
 * domain, its SPF records (there should only be one), and the record with the
 * IP added, when that would fix it.
 */
export async function check(ipText, email, resolve = dohResolve) {
    const ip = parseIp(ipText);
    if (!ip) {
        throw new TypeError(`"${ipText}" isn't an IP address`);
    }
    const at = email.lastIndexOf('@');
    const domain = email.slice(at + 1).toLowerCase();
    const local = (at > 0 && email.slice(0, at)) || 'postmaster';

    const state = { ip, local, domain, resolve, lookups: 0, records: [] };
    let status;
    let reason = null;
    try {
        status = await checkHost(state, domain, true);
    } catch (error) {
        if (!(error instanceof Stop)) {
            throw error;
        }
        ({ result: status, reason } = error);
    }
    status = status.toUpperCase();

    const { records } = state;
    const suggestion = records.length === 1 && ['FAIL', 'SOFTFAIL', 'NEUTRAL'].includes(status)
        ? withIp(records[0], ip)
        : null;

    return { status, reason, domain, records, suggestion };
}

/** The SPF record with the IP allowed first, e.g. "v=spf1 ip4:1.2.3.4 include:… ~all" */
export function withIp(record, ip) {
    const mechanism = ip.version === 4 ? 'ip4' : 'ip6';
    return `v=spf1 ${mechanism}:${ip.text}${record.slice('v=spf1'.length)}`;
}

/** The SPF result for a domain: pass, fail, softfail, neutral or none, or throws Stop */
async function checkHost(state, domain, first = false) {
    const records = (await lookup(state, domain, 'TXT'))
        .filter(txt => /^v=spf1( |$)/i.test(txt));
    if (first) {
        state.records = records;
    }
    if (records.length === 0) {
        return 'none';
    }
    if (records.length > 1) {
        throw new Stop('permerror');
    }

    const directives = [];
    let redirect;
    for (const term of records[0].split(/\s+/).slice(1).filter(Boolean)) {
        const modifier = term.match(/^([a-z][\w.-]*)=(.*)$/i);
        const directive = term.match(/^([-+~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)([:/].*)?$/i);
        if (modifier) {
            // other modifiers, like exp for rejection messages, aren't needed here
            if (modifier[1].toLowerCase() === 'redirect') {
                redirect ??= modifier[2];
            }
        } else if (directive) {
            const [, qualifier, name, value = ''] = directive;
            directives.push({ result: QUALIFIERS[qualifier || '+'], name: name.toLowerCase(), value });
        } else {
            throw invalid(term);
        }
    }

    for (const directive of directives) {
        if (await matches(state, domain, directive)) {
            return directive.result;
        }
    }

    if (redirect !== undefined) {
        countLookup(state);
        const redirectTo = target(state, redirect, domain);
        const result = await checkHost(state, redirectTo);
        if (result === 'none') {
            throw new Stop('permerror', `It redirects to ${redirectTo}, which has no SPF record.`);
        }
        return result;
    }
    return 'neutral';
}

/** If a mechanism, e.g. "ip4:1.2.3.0/24" (name ip4, value ":1.2.3.0/24"), matches the IP */
async function matches(state, domain, { name, value }) {
    const { ip } = state;

    switch (name) {
        case 'all':
            if (value) {
                throw invalid(name + value);
            }
            return true;

        case 'ip4':
        case 'ip6': {
            const [, network = '', prefix] = value.match(/^:([^/]+)(?:\/(\d+))?$/) ?? [];
            const parsed = parseIp(network);
            if (parsed?.version !== Number(name[2]) || prefix > parsed.bytes.length * 8) {
                throw invalid(name + value);
            }
            return inNetwork(ip, parsed, prefix);
        }

        case 'include': {
            countLookup(state);
            const included = target(state, domainSpec(name, value), domain);
            const result = await checkHost(state, included);
            if (result === 'none') {
                throw new Stop('permerror', `It includes ${included}, which has no SPF record.`);
            }
            return result === 'pass';
        }

        case 'a':
        case 'mx': {
            countLookup(state);
            // e.g. a, a:example.com, a/24, mx:example.com/24//64
            const parts = value.match(/^(?::(.+?))?(?:\/(\d+))?(?:\/\/(\d+))?$/);
            if (!parts) {
                throw invalid(name + value);
            }
            const [, spec, prefix4, prefix6] = parts;
            const host = target(state, spec, domain);
            const hosts = name === 'a' ? [host] : await lookup(state, host, 'MX');
            if (hosts.length > MAX_NAMES) {
                throw new Stop('permerror', `${host} has more than ${MAX_NAMES} MX records, which is SPF's limit for mx.`);
            }
            for (const host of hosts) {
                const addresses = await lookupAddresses(state, host);
                if (addresses.some(address => inNetwork(ip, address, ip.version === 4 ? prefix4 : prefix6))) {
                    return true;
                }
            }
            return false;
        }

        case 'ptr': {
            countLookup(state);
            const parent = target(state, value ? domainSpec(name, value) : undefined, domain);
            // the IP's host names in the domain, that point back to the IP. Lookups
            // that fail just don't match here, rather than failing the whole check.
            const hosts = (await lookup(state, reverseName(ip), 'PTR').catch(() => [])).slice(0, MAX_NAMES);
            for (const host of hosts.map(host => host.toLowerCase())) {
                if ((host === parent || host.endsWith(`.${parent}`))
                    && (await lookupAddresses(state, host).catch(() => [])).some(address => inNetwork(ip, address))) {
                    return true;
                }
            }
            return false;
        }

        case 'exists': {
            countLookup(state);
            // always an A lookup, whatever the IP version
            return (await lookup(state, target(state, domainSpec(name, value), domain), 'A')).length > 0;
        }
    }
}

/** The domain-spec in a mechanism's value, e.g. "_spf.example.com" from ":_spf.example.com" */
function domainSpec(name, value) {
    if (!value.startsWith(':')) {
        throw invalid(name + value);
    }
    return value.slice(1);
}

function countLookup(state) {
    if (++state.lookups > MAX_LOOKUPS) {
        throw new Stop('permerror',
            `It needs more than ${MAX_LOOKUPS} DNS lookups (counting the ones in what it includes), which is SPF's limit.`);
    }
}

async function lookup(state, name, type) {
    if (!isDomain(name)) {
        return [];
    }
    try {
        return await state.resolve(name, type);
    } catch (error) {
        if (error instanceof DnsError) {
            throw new Stop('temperror', `Looking up ${name}'s ${type} records failed, please try again in a moment.`);
        }
        throw error;
    }
}

/** A or AAAA records, to match the IP being checked */
async function lookupAddresses(state, name) {
    const records = await lookup(state, name, state.ip.version === 4 ? 'A' : 'AAAA');
    return records.map(parseIp).filter(Boolean);
}

function isDomain(name) {
    const labels = name.split('.');
    return labels.length > 1 && labels.every(label => /^[a-z0-9_-]{1,63}$/i.test(label));
}

/** The domain to look up for a mechanism or redirect, defaulting to the current domain */
function target(state, spec, domain) {
    const name = spec === undefined ? domain : expand(state, spec, domain);
    return name.replace(/\.$/, '').toLowerCase();
}

/** Fill in a domain-spec's macros, e.g. "%{ir}.%{v}._spf.%{d}" */
export function expand(state, spec, domain) {
    const { ip } = state;

    return spec.replace(MACRO, (token, letter, digits, reverse, delimiters) => {
        if (!letter) {
            return { '%%': '%', '%_': ' ', '%-': '%20' }[token];
        }
        const value = {
            s: `${state.local}@${state.domain}`,
            l: state.local,
            o: state.domain,
            d: domain,
            i: ip.version === 4 ? ip.bytes.join('.') : nibbles(ip).join('.'),
            // the IP's validated host name, which RFC 7208 says not to use
            p: 'unknown',
            v: ip.version === 4 ? 'in-addr' : 'ip6',
            // the HELO name, taken to be the email's domain here
            h: state.domain,
        }[letter.toLowerCase()];

        // e.g. %{d2} is the last 2 parts, %{ir} is reversed, %{l-} splits on - instead of .
        const delimiter = new RegExp(`[${(delimiters || '.').replace(/[-\\\]^]/g, '\\$&')}]`);
        let parts = value.split(delimiter);
        if (reverse) {
            parts.reverse();
        }
        if (digits) {
            parts = parts.slice(-Number(digits));
        }
        const expanded = parts.join('.');
        // upper case macros are URL encoded
        return letter === letter.toUpperCase() ? encodeURIComponent(expanded) : expanded;
    });
}

function reverseName(ip) {
    return ip.version === 4
        ? `${[...ip.bytes].reverse().join('.')}.in-addr.arpa`
        : `${nibbles(ip).reverse().join('.')}.ip6.arpa`;
}

function nibbles(ip) {
    return ip.bytes.flatMap(byte => [(byte >> 4).toString(16), (byte & 15).toString(16)]);
}

/**
 * An IP as { version, bytes, text }, or null if it isn't one. IPv4-mapped IPv6
 * addresses (::ffff:1.2.3.4) count as IPv4, as they do in SPF.
 */
export function parseIp(text) {
    const ipv4 = text.split('.');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) {
        // no leading zeros, as some read those as octal
        if (ipv4.some(part => Number(part) > 255 || String(Number(part)) !== part)) {
            return null;
        }
        return { version: 4, bytes: ipv4.map(Number), text };
    }

    // the URL parser checks IPv6 addresses, and gives them in their usual
    // form, e.g. 2001:db8::1 for 2001:0db8:0:0:0:0:0:0001
    if (!/^[0-9a-f:.]+$/i.test(text)) {
        return null;
    }
    let normal;
    try {
        normal = new URL(`http://[${text}]`).hostname.slice(1, -1);
    } catch {
        return null;
    }
    const [start, end] = normal.split('::').map(half => (half ? half.split(':') : []));
    const groups = [...start, ...Array(8 - start.length - (end?.length ?? 0)).fill('0'), ...(end ?? [])];
    const bytes = groups.flatMap(group => [parseInt(group, 16) >> 8, parseInt(group, 16) & 255]);

    if (bytes.slice(0, 10).every(byte => byte === 0) && bytes[10] === 255 && bytes[11] === 255) {
        return { version: 4, bytes: bytes.slice(12), text: bytes.slice(12).join('.') };
    }
    return { version: 6, bytes, text: normal };
}

/** If the IP is in the network, comparing the first `prefix` bits (all of them by default) */
function inNetwork(ip, network, prefix = 128) {
    return ip.version === network.version && ip.bytes.every((byte, i) => {
        const bits = Math.max(0, Math.min(8, prefix - i * 8));
        const mask = (0xff << (8 - bits)) & 0xff;
        return (byte & mask) === (network.bytes[i] & mask);
    });
}
