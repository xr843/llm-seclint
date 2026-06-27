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
