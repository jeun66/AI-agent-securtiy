from week4.taint import Tainted, taint_from_source, maybe_taint, is_tainted, collect_sources, check_http_get


def smoke_test_asserts():
    # 1) primitive taint from web
    v = taint_from_source("web:attacker", "secret")
    assert is_tainted(v) and "web:attacker" in collect_sources(v), "primitive taint failed"

    # 2) concatenation preserves taint
    a = taint_from_source("file:config", "token=")
    b = Tainted("123", ["file:config"])
    c = a + b
    assert is_tainted(c) and "file:config" in collect_sources(c), "concat taint failed"

    # 3) nested dict/list taint
    nested = taint_from_source("mcp:out", {"k": ["v1", "v2"]})
    assert is_tainted(nested) and "mcp:out" in collect_sources(nested), "nested taint failed"

    # 4) http_get sink blocks tainted url (query)
    url = Tainted("https://study.example/info?token=abc", ["file:config"]) 
    allowed, reason = check_http_get(url)
    assert (not allowed and reason == "tainted_url"), "http_get should block tainted URL"

    # 5) http_get allows untainted
    u2 = "https://study.example/info?lang=ko"
    allowed2, reason2 = check_http_get(u2)
    assert (allowed2 and reason2 == "allow"), "http_get should allow untainted URL"


if __name__ == "__main__":
    smoke_test_asserts()
