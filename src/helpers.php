<?php
// Helpers

use Mika56\SPFCheck\SPFCheck;
use Mika56\SPFCheck\DNSRecordGetterDirect;

// spf checker
function spfChecker(string $domain, string $ip) : array {
    $getter = new DNSRecordGetterDirect("8.8.8.8");
    $checker = new SPFCheck($getter);
    $spf = $getter->getSPFRecordForDomain($domain);
    $status = $checker->isIPAllowed($ip, $domain);

    // error type
    switch ($status) {
        case SPFCheck::RESULT_PASS: $status = 'PASS'; break;
        case SPFCheck::RESULT_FAIL: $status = 'FAIL'; break;
        case SPFCheck::RESULT_SOFTFAIL: $status = 'SOFTFAIL'; break;
        case SPFCheck::RESULT_NEUTRAL: $status = 'NEUTRAL'; break;
        case SPFCheck::RESULT_NONE: $status = 'NONE'; break;
        case SPFCheck::RESULT_PERMERROR: $status = 'PERMERROR'; break;
        case SPFCheck::RESULT_TEMPERROR:
        default:
            $status = 'TEMPERROR';
            break;
    }

    return [$status, $spf];
}

// get domain name from email address
function domainFromEmail(string $email) : string {
    $chunks = explode('@', $email);
    return end($chunks);
}
