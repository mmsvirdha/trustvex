# Tests for URL canonicalization rules (FEATURE_CONTRACT.md).

from ml.datasets.prepare import canonicalize_url


def test_lowercases_scheme_and_host():
    assert canonicalize_url("HTTPS://EXAMPLE.COM/Path") == "https://example.com/Path"


def test_preserves_path_case():
    assert canonicalize_url("https://example.com/CaseSensitive/Path") == "https://example.com/CaseSensitive/Path"


def test_strips_fragment():
    assert canonicalize_url("https://example.com/a#frag") == "https://example.com/a"


def test_sorts_query_params():
    assert canonicalize_url("https://example.com/?b=2&a=1") == "https://example.com/?a=1&b=2"


def test_empty_path_becomes_root_slash():
    assert canonicalize_url("https://example.com") == "https://example.com/"


def test_rejects_unparseable():
    assert canonicalize_url("not a url") is None


def test_rejects_missing_scheme():
    assert canonicalize_url("example.com/path") is None