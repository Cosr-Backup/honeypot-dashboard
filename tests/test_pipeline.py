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


class TestChineseLocalization:
    """Verify Chinese LOCALE text appears in generated HTML."""

    def test_html_contains_chinese_title(self, sample_log_lines, mock_geo_cache, mocker):
        """Generated HTML contains Chinese page title from LOCALE."""
        mocker.patch('generate.llm_generate', return_value='测试描述')
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
            html = generate.generate_html(data)
            assert generate.LOCALE['page_title'] in html
            assert generate.LOCALE['header_title'] in html
        finally:
            os.unlink(tmp)

    def test_html_contains_chinese_stats_labels(self, sample_log_lines, mock_geo_cache, mocker):
        """Generated HTML contains Chinese stats bar labels."""
        mocker.patch('generate.llm_generate', return_value='')
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
            html = generate.generate_html(data)
            assert generate.LOCALE['sessions_today'] in html
            assert generate.LOCALE['top_attackers'] in html
            assert generate.LOCALE['daily_breakdown'] in html
        finally:
            os.unlink(tmp)

    def test_html_lang_attribute_zh_cn(self, sample_log_lines, mock_geo_cache, mocker):
        """HTML lang attribute is set to zh-CN."""
        mocker.patch('generate.llm_generate', return_value='')
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
            html = generate.generate_html(data)
            assert 'lang="zh-CN"' in html
        finally:
            os.unlink(tmp)

    def test_locale_format_strings_render(self, sample_log_lines, mock_geo_cache, mocker):
        """LOCALE keys with {generated} placeholder render correctly."""
        mocker.patch('generate.llm_generate', return_value='')
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
            html = generate.generate_html(data)
            # footer should contain rendered timestamp, not raw {generated}
            assert '{generated}' not in html
            assert 'Cowrie SSH 蜜罐' in html
        finally:
            os.unlink(tmp)

    def test_no_english_ui_text_leaks(self, sample_log_lines, mock_geo_cache, mocker):
        """No leftover English UI text in generated HTML."""
        mocker.patch('generate.llm_generate', return_value='')
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
            html = generate.generate_html(data)
            # These English strings should NOT appear in the UI
            assert 'Sessions Today' not in html
            assert 'Top Attackers' not in html
            assert 'Login Attempts Today' not in html
            assert 'All-Time Stats' not in html
        finally:
            os.unlink(tmp)


# NOTE: TestCommandDeduplication (classify_commands_fast) was removed — that
# function is dead code the live generate.py deleted (H2 fix). Narrative
# generation is now covered by generate_attacker_narratives; the empty-command
# crash regression lives in test_parser.py::TestEmptyCommandRegression.
