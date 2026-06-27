"""Integration tests — full pipeline with snapshot testing."""
import json
import os
import tempfile
import pytest
from tests.conftest import _make_log_line

import generate


class TestFullPipeline:
    """End-to-end: sample log → parse → enrich → HTML."""

    def test_pipeline_produces_html(self, sample_log_lines, mock_geo_cache, mocker):
        """Full pipeline produces valid HTML output."""
        mocker.patch('generate.llm_generate', return_value='Automated scanner.')
        mocker.patch('generate._check_llm_once', return_value=False)
        mocker.patch('generate.load_cache', return_value={})
        mocker.patch('generate.save_cache')

        generate._nickname_cache.clear()
        generate._nickname_counter.clear()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('\n'.join(sample_log_lines))
            tmp = f.name
        try:
            events = generate.parse_log(tmp)
            assert len(events) > 0
            data = generate.analyze_events(events, mock_geo_cache)
            html = generate.generate_html(data)
            assert '<!DOCTYPE html>' in html or '<html' in html
            assert 'honeypot' in html.lower() or 'dashboard' in html.lower() or '<body' in html
            # Should contain stats
            assert str(data['stats']['total_sessions']) in html
        finally:
            os.unlink(tmp)

    def test_html_snapshot(self, sample_log_lines, mock_geo_cache, snapshot, mocker):
        """Snapshot test for HTML structure (catches silent regressions)."""
        mocker.patch('generate.llm_generate', return_value='Test narrative.')
        mocker.patch('generate._check_llm_once', return_value=False)
        mocker.patch('generate.load_cache', return_value={})
        mocker.patch('generate.save_cache')

        generate._nickname_cache.clear()
        generate._nickname_counter.clear()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('\n'.join(sample_log_lines))
            tmp = f.name
        try:
            events = generate.parse_log(tmp)
            data = generate.analyze_events(events, mock_geo_cache)
            # Normalize dynamic fields for stable snapshots
            data['generated'] = '2026-03-01 12:00:00 EST'
            html = generate.generate_html(data)
            # Snapshot a structural summary rather than full HTML (too large/dynamic)
            summary = {
                'has_doctype': '<!DOCTYPE' in html or '<!doctype' in html,
                'has_body': '<body' in html,
                'total_sessions_shown': str(data['stats']['total_sessions']) in html,
                'contains_attacker_ip': '1.2.3.4' in html,
                'html_length_approx': len(html) // 1000,  # KB rounded
            }
            assert summary == snapshot
        finally:
            os.unlink(tmp)


# NOTE: TestCommandDeduplication (classify_commands_fast) was removed — that
# function is dead code the live generate.py deleted (H2 fix). Narrative
# generation is now covered by generate_attacker_narratives; the empty-command
# crash regression lives in test_parser.py::TestEmptyCommandRegression.
