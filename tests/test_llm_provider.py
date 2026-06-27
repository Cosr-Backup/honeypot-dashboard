"""Tests for LLM provider configuration and branching.

Covers:
- LLM_PROVIDER validation (unknown → fallback to 'none')
- llm_generate branching across ollama/openai/none
- llm_healthy behavior per provider
"""
import json
import subprocess
import sys
import tempfile
import os
import pytest

import generate


class TestLLMProviderValidation:
    """LLM_PROVIDER env var validation at module load time."""

    def test_unknown_provider_warns_and_falls_back_to_none(self):
        """Unknown LLM_PROVIDER prints warning and sets provider to 'none'."""
        result = subprocess.run(
            [sys.executable, "-c",
             "import os; os.environ['LLM_PROVIDER']='typo_here'; "
             "import generate; print(generate.LLM_PROVIDER)"],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        assert "typo_here" in result.stderr
        assert "none" in result.stderr.lower() or result.stdout.strip() == "none"

    def test_valid_providers_accepted(self):
        """Valid LLM_PROVIDER values are accepted without warning."""
        for provider in ("ollama", "openai", "none"):
            result = subprocess.run(
                [sys.executable, "-c",
                 f"import os; os.environ['LLM_PROVIDER']='{provider}'; "
                 f"import generate; print(generate.LLM_PROVIDER)"],
                capture_output=True, text=True,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
            assert result.stdout.strip() == provider, \
                f"Provider '{provider}' not accepted: stderr={result.stderr}"


class TestLlmGenerateNone:
    """llm_generate returns empty string when provider is 'none'."""

    def test_none_provider_returns_empty(self, mocker):
        """With provider='none', llm_generate returns '' without any API call."""
        mocker.patch('generate.LLM_PROVIDER', 'none')
        mocker.patch('generate._llm_is_healthy', None)
        result = generate.llm_generate("test prompt")
        assert result == ""


class TestLlmGenerateOllama:
    """llm_generate with Ollama provider."""

    def test_ollama_calls_native_api(self, mocker):
        """Ollama provider calls /api/generate with native format."""
        mocker.patch('generate.LLM_PROVIDER', 'ollama')
        mocker.patch('generate._llm_is_healthy', True)
        mocker.patch('generate.OLLAMA_URL', 'http://localhost:11434')
        mocker.patch('generate.OLLAMA_MODEL', 'test-model')

        mock_resp = mocker.MagicMock()
        mock_resp.read.return_value = json.dumps({"response": "test output"}).encode()
        mock_resp.__enter__ = mocker.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mocker.MagicMock(return_value=False)

        mocker.patch('urllib.request.urlopen', return_value=mock_resp)

        result = generate.llm_generate("hello")
        assert result == "test output"

        # Verify the request was made to the Ollama endpoint
        call_args = generate.urllib.request.urlopen.call_args
        req = call_args[0][0]
        assert "api/generate" in req.full_url

    def test_ollama_failure_returns_empty(self, mocker):
        """Ollama API failure returns empty string, no crash."""
        mocker.patch('generate.LLM_PROVIDER', 'ollama')
        mocker.patch('generate._llm_is_healthy', True)
        mocker.patch('urllib.request.urlopen', side_effect=ConnectionError("refused"))

        result = generate.llm_generate("hello")
        assert result == ""


class TestLlmGenerateOpenAI:
    """llm_generate with OpenAI-compatible provider."""

    def test_openai_calls_chat_completions(self, mocker):
        """OpenAI provider calls /v1/chat/completions with messages format."""
        mocker.patch('generate.LLM_PROVIDER', 'openai')
        mocker.patch('generate._llm_is_healthy', True)
        mocker.patch('generate.LLM_API_BASE', 'https://api.openai.com/v1')
        mocker.patch('generate.LLM_API_KEY', 'sk-test')
        mocker.patch('generate.LLM_MODEL', 'gpt-test')

        mock_resp = mocker.MagicMock()
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": "openai output"}}]
        }).encode()
        mock_resp.__enter__ = mocker.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mocker.MagicMock(return_value=False)

        mock_req = mocker.MagicMock()
        mocker.patch('urllib.request.Request', return_value=mock_req)
        mocker.patch('urllib.request.urlopen', return_value=mock_resp)

        result = generate.llm_generate("hello")
        assert result == "openai output"

        # Verify Authorization header was added
        mock_req.add_header.assert_called_with("Authorization", "Bearer sk-test")

    def test_openai_empty_key_no_auth_header(self, mocker):
        """OpenAI provider with empty key does not add Authorization header."""
        mocker.patch('generate.LLM_PROVIDER', 'openai')
        mocker.patch('generate._llm_is_healthy', True)
        mocker.patch('generate.LLM_API_BASE', 'https://api.example.com/v1')
        mocker.patch('generate.LLM_API_KEY', '')
        mocker.patch('generate.LLM_MODEL', 'test')

        mock_resp = mocker.MagicMock()
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": "ok"}]
        }).encode()
        mock_resp.__enter__ = mocker.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mocker.MagicMock(return_value=False)

        mock_req = mocker.MagicMock()
        mocker.patch('urllib.request.Request', return_value=mock_req)
        mocker.patch('urllib.request.urlopen', return_value=mock_resp)

        generate.llm_generate("hello")
        # add_header should NOT have been called with Authorization
        for call in mock_req.add_header.call_args_list:
            assert call[0][0] != "Authorization", \
                "Authorization header added despite empty API key"

    def test_openai_failure_returns_empty(self, mocker):
        """OpenAI API failure returns empty string, no crash."""
        mocker.patch('generate.LLM_PROVIDER', 'openai')
        mocker.patch('generate._llm_is_healthy', True)
        mocker.patch('generate.LLM_API_BASE', 'https://api.example.com/v1')
        mocker.patch('generate.LLM_API_KEY', '')
        mocker.patch('urllib.request.urlopen', side_effect=TimeoutError("timeout"))

        result = generate.llm_generate("hello")
        assert result == ""


class TestLlmHealthy:
    """llm_healthy behavior per provider."""

    def test_none_provider_returns_false(self):
        """Provider 'none' always returns False."""
        original = generate.LLM_PROVIDER
        generate.LLM_PROVIDER = "none"
        try:
            assert generate.llm_healthy() is False
        finally:
            generate.LLM_PROVIDER = original

    def test_ollama_checks_api_tags(self, mocker):
        """Ollama provider checks /api/tags endpoint."""
        mocker.patch('generate.LLM_PROVIDER', 'ollama')
        mocker.patch('generate.OLLAMA_URL', 'http://localhost:11434')

        mock_resp = mocker.MagicMock()
        mock_resp.status = 200
        mocker.patch('urllib.request.urlopen', return_value=mock_resp)

        assert generate.llm_healthy() is True
        call_args = generate.urllib.request.urlopen.call_args
        req = call_args[0][0]
        assert "api/tags" in req.full_url

    def test_openai_checks_models_endpoint(self, mocker):
        """OpenAI provider checks /models endpoint with auth header."""
        mocker.patch('generate.LLM_PROVIDER', 'openai')
        mocker.patch('generate.LLM_API_BASE', 'https://api.openai.com/v1')
        mocker.patch('generate.LLM_API_KEY', 'sk-test')

        mock_resp = mocker.MagicMock()
        mock_resp.status = 200
        mock_req = mocker.MagicMock()
        mocker.patch('urllib.request.Request', return_value=mock_req)
        mocker.patch('urllib.request.urlopen', return_value=mock_resp)

        assert generate.llm_healthy() is True
        mock_req.add_header.assert_called_with("Authorization", "Bearer sk-test")

    def test_unreachable_returns_false(self, mocker):
        """Unreachable LLM endpoint returns False."""
        mocker.patch('generate.LLM_PROVIDER', 'ollama')
        mocker.patch('urllib.request.urlopen', side_effect=ConnectionError("refused"))
        assert generate.llm_healthy() is False


class TestCheckLlmOnce:
    """_check_llm_once caches result and prints appropriate messages."""

    def test_none_provider_prints_disabled_message(self, mocker, capsys):
        """Provider 'none' prints disabled message."""
        mocker.patch('generate.LLM_PROVIDER', 'none')
        generate._llm_is_healthy = None  # reset cache
        try:
            result = generate._check_llm_once()
            assert result is False
            captured = capsys.readouterr()
            assert "disabled" in captured.out.lower() or "none" in captured.out.lower()
        finally:
            generate._llm_is_healthy = None

    def test_caches_result(self, mocker):
        """Subsequent calls return cached result without re-checking."""
        mocker.patch('generate.LLM_PROVIDER', 'ollama')
        generate._llm_is_healthy = True  # pre-set cache
        try:
            # Should not call llm_healthy at all
            mock_healthy = mocker.patch('generate.llm_healthy')
            result = generate._check_llm_once()
            assert result is True
            mock_healthy.assert_not_called()
        finally:
            generate._llm_is_healthy = None
