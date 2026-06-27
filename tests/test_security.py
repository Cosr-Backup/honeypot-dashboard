"""Security tests — XSS prevention in honeypot dashboard.

The dashboard renders ADVERSARIAL input (attacker-controlled commands,
credentials, user-agents). Every user-supplied string that appears in
HTML output must be escaped.
"""
import json
import os
import tempfile
import pytest
from tests.conftest import XSS_PAYLOADS, _make_log_line

import generate


class TestXSSInCredentials:
    """Attacker-controlled usernames and passwords must be escaped in HTML."""

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_username_escaped_in_html(self, payload, mock_geo_cache):
        """XSS payload in username field must not appear raw in HTML output."""
        lines = [
            _make_log_line("cowrie.session.connect", src_ip="10.0.0.1"),
            _make_log_line("cowrie.login.failed", src_ip="10.0.0.1",
                           username=payload, password="safe"),
        ]
        html = _generate_html_from_lines(lines, mock_geo_cache)
        assert payload not in html, f"Raw XSS payload found in HTML: {payload}"

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_password_escaped_in_html(self, payload, mock_geo_cache):
        """XSS payload in password field must not appear raw in HTML output."""
        lines = [
            _make_log_line("cowrie.session.connect", src_ip="10.0.0.1"),
            _make_log_line("cowrie.login.failed", src_ip="10.0.0.1",
                           username="root", password=payload),
        ]
        html = _generate_html_from_lines(lines, mock_geo_cache)
        assert payload not in html, f"Raw XSS payload found in HTML: {payload}"


class TestXSSInCommands:
    """Attacker-controlled commands must be escaped in HTML."""

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_command_escaped_in_html(self, payload, mock_geo_cache):
        """XSS payload in command input must not appear raw in HTML output."""
        lines = [
            _make_log_line("cowrie.session.connect", src_ip="10.0.0.1"),
            _make_log_line("cowrie.login.success", src_ip="10.0.0.1",
                           username="root", password="toor"),
            _make_log_line("cowrie.command.input", src_ip="10.0.0.1",
                           input=payload),
        ]
        html = _generate_html_from_lines(lines, mock_geo_cache)
        assert payload not in html, f"Raw XSS payload found in HTML: {payload}"


class TestXSSInNarratives:
    """LLM-generated narratives and stories must not pass through raw XSS."""

    def test_story_with_xss_escaped(self, mock_geo_cache, mocker):
        """If LLM returns XSS in narrative, it must be escaped in HTML."""
        mocker.patch('generate.llm_generate', return_value='<script>alert("pwned")</script>')
        mocker.patch('generate._check_llm_once', return_value=True)
        lines = [
            _make_log_line("cowrie.session.connect", src_ip="10.0.0.1"),
            _make_log_line("cowrie.login.success", src_ip="10.0.0.1",
                           username="root", password="toor"),
            _make_log_line("cowrie.command.input", src_ip="10.0.0.1",
                           input="uname -a"),
        ]
        html = _generate_html_from_lines(lines, mock_geo_cache)
        assert '<script>alert("pwned")</script>' not in html


def _generate_html_from_lines(lines, geo_cache):
    """Helper: parse log lines → analyze → generate HTML."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('\n'.join(lines))
        f.flush()
        tmp_path = f.name
    try:
        # Reset nickname caches between tests
        generate._nickname_cache.clear()
        generate._nickname_counter.clear()
        events = generate.parse_log(tmp_path)
        data = generate.analyze_events(events, geo_cache)
        html = generate.generate_html(data)
        return html
    finally:
        os.unlink(tmp_path)
