"""W4 regression tests: derived values may not lose provenance."""
import pytest
from week4.taint import Tainted, collect_sources, is_tainted, check_http_get


@pytest.mark.parametrize("name,args", [
    ("split", ()), ("split", ("/",)), ("rsplit", ("/",)),
    ("splitlines", ()), ("partition", ("/",)), ("rpartition", ("/",)),
])
def test_string_methods_preserve_container_sources(name, args):
    raw = Tainted("https://study.example/info", {"external"})
    result = getattr(raw, name)(*args)
    assert isinstance(result, (tuple, list))
    assert collect_sources(result) == {"external"}
    assert all(isinstance(part, Tainted) for part in result)


def test_tainted_split_stops_real_mock_sink():
    candidate = Tainted("https://study.example/info", {"external"}).split()[0]
    assert check_http_get(candidate) == (False, "tainted_url")
    assert is_tainted([candidate])


def test_join_slice_and_tuple_keep_sources():
    value = Tainted("https://", {"user"}).join([Tainted("study.example", {"web"}), "/info"])
    assert value.value == "https://study.example/info"
    assert value.sources == {"user", "web"}
    assert value[:5].sources == value.sources
    assert collect_sources((value,)) == value.sources
    assert not is_tainted(Tainted("a b").split())


def test_join_rejects_non_string_element():
    with pytest.raises(TypeError):
        Tainted("-").join([1])
