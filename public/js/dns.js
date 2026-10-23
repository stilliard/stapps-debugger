// DNS lookups from the browser, using Cloudflare's DNS over HTTPS JSON API.
// https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/

const TYPES = { A: 1, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };

/** A lookup that failed, e.g. a timeout or SERVFAIL, rather than finding nothing */
export class DnsError extends Error {}

/**
 * The records of a type for a name, as strings: IPs for A/AAAA, host names for
 * MX/PTR, and the joined-up text for TXT. Names that don't exist give [].
 */
export async function resolve(name, type) {
    const url = 'https://cloudflare-dns.com/dns-query?' + new URLSearchParams({ name, type });
    let response;
    try {
        response = await fetch(url, {
            headers: { accept: 'application/dns-json' },
            signal: AbortSignal.timeout(5000),
        });
    } catch (error) {
        throw new DnsError(`${type} lookup for ${name} failed: ${error.message}`);
    }
    if (!response.ok) {
        throw new DnsError(`${type} lookup for ${name} failed: HTTP ${response.status}`);
    }

    const { Status, Answer = [] } = await response.json();
    // 0 is NOERROR, 3 is NXDOMAIN (the name doesn't exist)
    if (Status === 3) {
        return [];
    }
    if (Status !== 0) {
        throw new DnsError(`${type} lookup for ${name} failed: DNS status ${Status}`);
    }

    return Answer
        // the answer can include CNAMEs followed on the way
        .filter(answer => answer.type === TYPES[type])
        .map(({ data }) => {
            switch (type) {
                case 'TXT': return txtData(data);
                case 'MX': return stripDot(data.split(' ')[1]);
                case 'PTR': return stripDot(data);
                default: return data;
            }
        });
}

/** TXT data comes as quoted strings, e.g. `"v=spf1 ip4:1.2.3.4 " "-all"`, joined into one */
export function txtData(data) {
    if (!data.startsWith('"')) {
        return data;
    }
    let text = '';
    for (const [, quoted] of data.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
        text += quoted.replace(/\\(\d{3}|.)/g, (_, escaped) =>
            escaped.length === 3 ? String.fromCharCode(Number(escaped)) : escaped);
    }
    return text;
}

function stripDot(name) {
    return name.replace(/\.$/, '');
}
