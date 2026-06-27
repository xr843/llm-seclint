"""Tests for LS009: SSRF via LLM/user output used as a request URL."""

from __future__ import annotations

from pathlib import Path

from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
from llm_seclint.core.finding import Finding
from llm_seclint.rules.python.ssrf import SsrfRule
from tests.conftest import run_rule_on_code


def _rule() -> SsrfRule:
    return SsrfRule()


def _scan(code: str) -> list[Finding]:
    findings, _ = PythonAnalyzer([_rule()]).analyze(code, Path("app.py"))
    return [f for f in findings if f.rule_id == "LS009"]


_USER = "url = request.args.get('u')\n"
_LLM = "url = litellm.completion(model='m').content\n"


class TestLs009Confirmed:
    def test_requests_get_user(self) -> None:
        f = _scan(_USER + "requests.get(url)\n")
        assert len(f) == 1
        assert f[0].rule_id == "LS009"
        assert f[0].taint_source == "user"
        assert "ssrf" in f[0].message.lower()

    def test_httpx_post_url_kwarg_llm(self) -> None:
        f = _scan(_LLM + "httpx.post(url=url, json={})\n")
        assert len(f) == 1
        assert f[0].taint_source == "llm"

    def test_urlopen_user(self) -> None:
        f = _scan(_USER + "urllib.request.urlopen(url)\n")
        assert len(f) == 1

    def test_bare_urlopen_user(self) -> None:
        f = _scan(_USER + "urlopen(url)\n")
        assert len(f) == 1


class TestLs009NotReported:
    def test_static_url(self) -> None:
        assert _scan("requests.get('https://api.example.com')\n") == []

    def test_dynamic_but_unconfirmed_url(self) -> None:
        # Taint-gated: a dynamic URL with no untrusted source is not SSRF.
        assert _scan("base = settings.API\nrequests.get(base)\n") == []

    def test_non_http_get_is_not_a_sink(self) -> None:
        # dict.get / session.get must not be treated as an HTTP sink.
        assert _scan(_USER + "cache.get(url)\n") == []
        assert _scan(_USER + "mydict.get(url)\n") == []

    def test_no_taint_context_silent(self) -> None:
        assert run_rule_on_code(_rule(), "requests.get(u)\n") == []

    def test_rule_is_stable(self) -> None:
        assert _rule().stability == "stable"


class TestLs009SessionSinks:
    def test_requests_session_var(self) -> None:
        f = _scan("s = requests.Session()\n" + _USER + "s.get(url)\n")
        assert len(f) == 1
        assert f[0].taint_source == "user"

    def test_httpx_client_var(self) -> None:
        f = _scan("client = httpx.Client()\n" + _LLM + "client.post(url)\n")
        assert len(f) == 1

    def test_aiohttp_session_var(self) -> None:
        f = _scan("session = aiohttp.ClientSession()\n" + _USER + "session.get(url)\n")
        assert len(f) == 1

    def test_inline_session_ctor(self) -> None:
        f = _scan(_USER + "requests.Session().get(url)\n")
        assert len(f) == 1

    def test_non_session_var_get_not_sink(self) -> None:
        # a plain variable's .get is NOT a sink (only tracked session vars are).
        assert _scan("cache = make_cache()\n" + _USER + "cache.get(url)\n") == []

    def test_request_method_url_is_second_arg(self) -> None:
        # requests.request("GET", url) — url is the 2nd positional arg.
        f = _scan(_USER + "requests.request('GET', url)\n")
        assert len(f) == 1
        assert f[0].taint_source == "user"

    def test_session_request_method_second_arg(self) -> None:
        f = _scan("s = requests.Session()\n" + _USER + "s.request('GET', url)\n")
        assert len(f) == 1

    def test_urllib3_poolmanager_request(self) -> None:
        f = _scan("pool = urllib3.PoolManager()\n" + _USER + "pool.request('GET', url)\n")
        assert len(f) == 1


class TestLs009SessionVarCollision:
    """A name reused as a non-session object must not become an SSRF sink."""

    def test_reassigned_to_dict_not_sink(self) -> None:
        code = (
            "s = requests.Session()\n"
            "s = {}\n"
            "u = request.args.get('x')\n"
            "s.get(u)\n"
        )
        assert _scan(code) == []

    def test_cross_function_name_collision_not_sink(self) -> None:
        # `client` is an httpx session in one function and a redis client in
        # another — its redis .get(key) must not be flagged as SSRF.
        code = (
            "def fetch(u):\n"
            "    client = httpx.Client()\n"
            "    return client.get(u)\n"
            "def lookup():\n"
            "    client = get_redis()\n"
            "    key = request.args.get('k')\n"
            "    return client.get(key)\n"
        )
        assert _scan(code) == []
