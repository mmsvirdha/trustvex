# TRUSTVEX URL Feature Contract v1.0

This document defines the 12 URL-string features used by the ML model v1.
Both the TypeScript scanner (`src/lib/analyzers/urlAnalyzer.ts`) and the
Python training pipeline (`ml/datasets/prepare.py`) must conform to these
definitions.

If the two implementations disagree on a feature for a given URL, that is a
bug in one of them — except for `subdomain_count`, where a documented
divergence is allowed (see below).

## Features

### 1. `url_length` (int, >= 0)
Character count of the submitted URL string after canonicalization
(scheme lowercased, hostname lowercased, path unchanged, query params
sorted, fragment stripped). Trailing `/` is preserved for non-root paths
and stripped for root paths.

### 2. `hostname_length` (int, >= 0)
Character count of the hostname portion of the URL, as returned by the
standard URL parser.

### 3. `path_length` (int, >= 0)
Character count of the path, from `/` up to (but not including) `?` or
`#`. For root URLs, path is `/`, so `path_length == 1`.

### 4. `query_length` (int, >= 0)
Character count of the query string after the leading `?` and before any
fragment. `0` if no query string.

### 5. `subdomain_count` (int, >= 0)
Number of hostname labels strictly before the registrable domain, using
the Public Suffix List. Examples:
- `example.com` -> 0
- `www.example.com` -> 1
- `a.b.example.com` -> 2
- `example.co.uk` -> 0
- `www.example.co.uk` -> 1

**Documented divergence (D3.1):** The TypeScript analyzer currently uses
a simplified two-label heuristic and will report a different
`subdomain_count` for domains under multi-label public suffixes. The
Python pipeline uses the Public Suffix List. This divergence is allowed
during v1 and will be closed in a later milestone.

### 6. `digit_count` (int, >= 0)
Number of ASCII digits in the URL string.

### 7. `special_char_count` (int, >= 0)
Number of characters in the URL string that are not in
`[a-zA-Z0-9.:/?&=_-#]`.

### 8. `has_ip_hostname` (bool)
True if the hostname is an IPv4 dotted-quad or an IPv6 bracket literal.

### 9. `has_punycode` (bool)
True if any hostname label begins with `xn--`.

### 10. `has_embedded_credentials` (bool)
True if the URL contains a non-empty username or password segment.

### 11. `has_unusual_port` (bool)
True if the URL specifies a port and that port is not `80` or `443`.

### 12. `suspicious_keyword_count` (int, >= 0)
Number of matches from this fixed keyword list found in the lowercased
URL string:

login, verify, secure, account, update, confirm, signin, banking,
billing, password, wallet, recover, unlock, suspended



## Cross-implementation validation

`ml/datasets/tests/test_feature_parity.py` runs 100 representative URLs
through both implementations and asserts parity on all 12 features,
except for `subdomain_count` on domains under multi-label public suffixes
where the documented divergence above is allowed.