"""Tests for AI Suricata rule generation helpers."""

from app.services.llm.suricata_rule_writer import _next_sid_hint, _used_sids


def test_used_sids_parsing():
    text = 'alert tcp any any -> $HOME_NET 22 (msg:"x"; sid:1000001; rev:1;)\nalert tcp any any -> any any (sid:1000002; rev:1;)'
    assert _used_sids(text) == {1000001, 1000002}
    assert _next_sid_hint(text) == 1000003


def test_next_sid_empty():
    assert _next_sid_hint("") >= 1000200
