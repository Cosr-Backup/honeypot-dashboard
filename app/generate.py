#!/usr/bin/env python3
"""
Cowrie Honeypot Dashboard Generator
Parses Cowrie JSON logs, does GeoIP lookups, generates a self-contained HTML dashboard.

Fixes applied (2026-02-06):
- H3: Atomic writes (temp+rename) for geoip_cache.json and description_cache.json
- L5: Moved imports (math, random, re) to top of file
- L7: Bare except → specific exception types in load_cache()
- M5: Seed random with IP hash for deterministic command explanations

Fixes applied (2026-03-24) - Pike:
- H1/H3: Shared desc_cache between generate_greatest_hits and generate_attacker_narratives
         (single load + single save per generate_html run, no partial-write race)
- H2: Removed dead classify_commands_fast function (~80 lines, never called)
- M1: Consolidated inline _bad_starts lists into module-level _BAD_PREFIXES
"""

import glob
import gzip
import hashlib
import json
import math
import os
import random
import re
import sys
import tempfile
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from html import escape as h
from zoneinfo import ZoneInfo

LOCAL_TZ = ZoneInfo("America/New_York")

# ── 本地化字典 ──────────────────────────────────────────────────
_LOCALE_ZH = {
    # 页面级
    "lang": "zh-CN",
    "page_title": "蜜罐攻击态势仪表盘",
    "header_title": "🍯 蜜罐攻击态势仪表盘",
    "header_subtitle": "COWRIE SSH 蜜罐 // 实时攻击情报 // 生成于: {generated}",
    "footer": "蜜罐攻击态势仪表盘 v1.0 // 数据来源: Cowrie SSH 蜜罐 // {generated}",
    # 统计栏
    "sessions_today": "今日会话",
    "login_attempts_today": "今日登录尝试",
    "successful_logins_today": "今日成功登录",
    "unique_ips_today": "今日独立 IP",
    "commands_today": "今日命令",
    # 面板标题
    "attack_origins": "🌐 攻击来源",
    "top_attackers": "🏆 攻击者排行",
    "recent_activity": "📡 最近活动",
    "greatest_hits": "🎬 精彩回顾",
    "top_credentials": "🔑 高频凭证",
    "attack_timeline": "📈 攻击时间线",
    "daily_breakdown": "📊 每日明细",
    "all_time_stats": "📊 历史统计",
    "successful_logins_detail": "💀 成功登录 — 攻击者行为",
    # 表头 — 攻击者排行
    "th_attacker": "攻击者",
    "th_origin": "来源",
    "th_isp": "运营商",
    "th_attempts": "尝试次数",
    # 表头 — 每日明细
    "th_date": "日期",
    "th_sessions": "会话",
    "th_login_attempts": "登录尝试",
    "th_successful": "成功",
    "th_unique_ips": "独立 IP",
    "th_commands": "命令",
    "th_top_attacker": "主要攻击者",
    # 表头 — 历史统计
    "th_metric": "指标",
    "th_total": "总计",
    "th_avg_day": "日均",
    "th_last_24h": "近 24h",
    "th_peak_day": "峰值日",
    # 历史统计行标签
    "metric_sessions": "会话",
    "metric_login_attempts": "登录尝试",
    "metric_successful_logins": "成功登录",
    "metric_unique_ips": "独立 IP",
    "metric_commands_executed": "执行命令",
    "metric_success_rate": "成功率",
    "metric_days_active": "活跃天数",
    # 地图弹窗
    "popup_creds_tried": "尝试凭证:",
    "popup_location": "位置:",
    "popup_isp": "运营商:",
    "popup_attempts": "尝试次数:",
    # 图表
    "chart_label_attempts": "尝试次数",
    # 动态/空状态
    "no_attackers": "暂无攻击者数据。",
    "no_successful_logins": "暂无成功登录记录。机器人仍在努力尝试中...",
    "login_success": "✅ 登录成功",
    "key_auth": "🔑 密钥认证",
    "login_attempt": "登录尝试",
    "command_prefix": "命令:",
    "file_prefix": "文件:",
    # 日期月份缩写（JavaScript 用，渲染时通过 json.dumps 转换）
    "months": ["1月","2月","3月","4月","5月","6月","7月","8月","9月","10月","11月","12月"],
    # 量词/单位
    "unit_attempts": " 次尝试",
    "unit_sessions": " 个会话",
    "unit_cmds": " 条命令",
}

_LOCALE_EN = {
    "lang": "en",
    "page_title": "Honeypot Dashboard",
    "header_title": "🍯 Honeypot Dashboard",
    "header_subtitle": "COWRIE SSH HONEYPOT // LIVE ATTACKER INTELLIGENCE // Generated: {generated}",
    "footer": "Honeypot Dashboard v1.0 // Data from Cowrie SSH Honeypot // {generated}",
    "sessions_today": "Sessions Today",
    "login_attempts_today": "Login Attempts Today",
    "successful_logins_today": "Successful Logins Today",
    "unique_ips_today": "Unique IPs Today",
    "commands_today": "Commands Today",
    "attack_origins": "🌐 Attack Origins",
    "top_attackers": "🏆 Top Attackers",
    "recent_activity": "📡 Recent Activity",
    "greatest_hits": "🎬 Greatest Hits",
    "top_credentials": "🔑 Top Credentials",
    "attack_timeline": "📈 Attack Timeline",
    "daily_breakdown": "📊 Daily Breakdown",
    "all_time_stats": "📊 All-Time Stats",
    "successful_logins_detail": "💀 Successful Logins — What They Did",
    "th_attacker": "Attacker",
    "th_origin": "Origin",
    "th_isp": "ISP",
    "th_attempts": "Attempts",
    "th_date": "Date",
    "th_sessions": "Sessions",
    "th_login_attempts": "Login Attempts",
    "th_successful": "Successful",
    "th_unique_ips": "Unique IPs",
    "th_commands": "Commands",
    "th_top_attacker": "Top Attacker",
    "th_metric": "Metric",
    "th_total": "Total",
    "th_avg_day": "Avg / Day",
    "th_last_24h": "Last 24h",
    "th_peak_day": "Peak Day",
    "metric_sessions": "Sessions",
    "metric_login_attempts": "Login Attempts",
    "metric_successful_logins": "Successful Logins",
    "metric_unique_ips": "Unique IPs",
    "metric_commands_executed": "Commands Executed",
    "metric_success_rate": "Success Rate",
    "metric_days_active": "Days Active",
    "popup_creds_tried": "Creds tried:",
    "popup_location": "Location:",
    "popup_isp": "ISP:",
    "popup_attempts": "Attempts:",
    "chart_label_attempts": "Attempts",
    "no_attackers": "No attackers to profile yet.",
    "no_successful_logins": "No successful logins captured yet. The bots are still trying...",
    "login_success": "✅ LOGIN SUCCESS",
    "key_auth": "🔑 Key auth",
    "login_attempt": "Login attempt",
    "command_prefix": "Command:",
    "file_prefix": "File:",
    "months": ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
    "unit_attempts": " attempts",
    "unit_sessions": " sessions",
    "unit_cmds": " cmds",
}

_LOCALES = {"zh": _LOCALE_ZH, "en": _LOCALE_EN}
_LANG = os.environ.get("LANG", "zh").split("-")[0].lower()  # "zh-CN" → "zh", "en" → "en"
LOCALE = _LOCALES.get(_LANG, _LOCALE_ZH)

def strip_markdown(text):
    """Strip markdown formatting from LLM output before inserting into HTML."""
    if not text:
        return text
    # Remove headers (### Header -> Header)
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    # Remove bold/italic markers
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    text = re.sub(r'__(.+?)__', r'\1', text)
    text = re.sub(r'_(.+?)_', r'\1', text)
    # Remove inline code backticks
    text = re.sub(r'`(.+?)`', r'\1', text)
    # Remove code blocks
    text = re.sub(r'```[\s\S]*?```', '', text)
    # Remove horizontal rules
    text = re.sub(r'^---+$', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\*\*\*+$', '', text, flags=re.MULTILINE)
    # Remove bullet points
    text = re.sub(r'^\s*[-*+]\s+', '', text, flags=re.MULTILINE)
    # Remove numbered lists prefix
    text = re.sub(r'^\s*\d+\.\s+', '', text, flags=re.MULTILINE)
    # Collapse multiple newlines/whitespace
    text = re.sub(r'\n+', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    # Final safety: remove any remaining markdown artifacts
    text = text.replace('**', '').replace('__', '').replace('`', '')
    # Remove any leftover # at start of text
    text = re.sub(r'^#+\s*', '', text)
    return text.strip()


# Meta-phrase patterns that indicate bad LLM output
_BAD_PREFIXES = [
    "based on the", "here is the", "here is a", "here's the", "here's a",
    "as an ai", "i'll analyze", "i will analyze", "let me analyze",
    "the following", "this is a", "this is the", "i can see",
    "looking at the", "analyzing the", "the attacker profile",
    "attacker profile:", "summary:", "analysis:",
    "(do not include", "arrow-chain summary",
    "attacker:", "attacker profile", "the attacker",
    # Inline bad-starts from generate_greatest_hits / generate_attacker_narratives (M1 fix)
    "here", "i can", "we ", "okay",
    "this command", "it looks", "the user", "based on",
    "sure",
]


def validate_llm_output(text, max_chars=300):
    """Check if LLM output is good quality. Returns (is_valid, reason)."""
    if not text:
        return False, "empty"
    text_lower = text.lower().strip()
    for prefix in _BAD_PREFIXES:
        if text_lower.startswith(prefix):
            return False, f"meta-prefix: {prefix}"
    if len(text) > max_chars:
        return False, f"too long ({len(text)} chars)"
    # Check for any residual markdown
    if re.search(r'^#{1,6}\s', text, re.MULTILINE):
        return False, "contains markdown headers"
    if '**' in text:
        return False, "contains bold markdown"
    if '`' in text:
        return False, "contains backtick markdown"
    # Reject descriptions that just restate stats (attempt counts, session counts)
    if re.match(r'^\d[\d,]*\s+(attempts?|sessions?|commands?)', text_lower):
        return False, "just restates stats"
    # Reject descriptions that are just country/ISP metadata
    if re.match(r'^(attacker:?\s+)?(from\s+)?[A-Z][a-z]+[,\s]', text) and len(text) < 80:
        # Check if it's mostly proper nouns and metadata (no action verbs)
        action_words = ["brute", "scan", "target", "credential", "dump", "download",
                        "execute", "deploy", "persist", "recon", "fingerprint", "probe",
                        "exploit", "attack", "compromise", "harvest", "spray", "stuff",
                        "audit", "profile", "pivot", "shell", "payload", "miner", "botnet"]
        if not any(w in text_lower for w in action_words):
            return False, "just metadata, no attack description"
    return True, "ok"


# === Prompt Routing System ===
# Tested prompts from honeypot-prompt-routing.md
# Pike <pike@brezgis.com> 2026-03-22

PROMPT_SOPHISTICATED = (
    "你是一名蜜罐安全分析员，为仪表盘撰写一句话攻击者描述。\n"
    "技术精确、风格冷峻。幽默感来自攻击者实际的行为。\n\n"
    "规则：\n"
    "- 只根据日志中实际出现的行为判断，不要编造或推测未出现的动作\n"
    "- 一句话，不超过 200 字符\n"
    "- 不要使用 markdown、反引号或列表\n"
    "- 不要以\"攻击者\"开头\n"
    "- 不要重复元数据（国家、IP、运营商）\n"
    "- 不要提及\"蜜罐\"\n"
    "- 以最有趣的技术行为开头\n"
    "- 不要给出攻击教学或建议\n\n"
    "示例：\n"
    "- \"chattr 锁了 .ssh，注入 mdrfckr 公钥，改了 root 密码，还盘点了硬件——一个会话内完成的教科书式接管。\"\n"
    "- \"把 uname -a 写进脚本，chmod 777，然后执行——明明可以直接打的，但仪式感不能少。\"\n\n"
    "用一句话描述这个攻击者：\n"
    "{profile}"
)

PROMPT_RECON = (
    "你是一名蜜罐安全分析员，为仪表盘撰写一句话攻击者描述。\n"
    "技术精确、风格冷峻。\n\n"
    "规则：\n"
    "- 只根据日志中实际出现的行为判断，不要编造或推测未出现的动作\n"
    "- 一句话，不超过 200 字符\n"
    "- 不要使用 markdown、反引号\n"
    "- 不要以\"攻击者\"开头\n"
    "- 不要重复元数据（国家、IP、运营商）\n"
    "- 不要提及\"蜜罐\"\n"
    "- 突出重复行为或徒劳感\n"
    "- 如果命令很少，只说明其进行了基础探测，不要夸大\n\n"
    "示例：\n"
    "- \"3951 次会话跑的都是同一个 uname 命令，配着 Solana 凭证——对单调的执着令人敬佩。\"\n"
    "- \"带着验证器凭证来了，跑了四次 uname，走了——窗口购物找加密节点。\"\n\n"
    "用一句话描述这个攻击者：\n"
    "{profile}"
)

PROMPT_BOMBER = (
    "你为安全仪表盘撰写简短、面无表情的一句话描述。\n"
    "让事实本身的荒谬感来说话。\n\n"
    "规则：\n"
    "- 只根据日志中实际出现的行为判断，不要编造\n"
    "- 一句话，不超过 200 字符\n"
    "- 不要使用 markdown、反引号\n"
    "- 不要以\"攻击者\"开头\n"
    "- 不要重复元数据（国家、IP、运营商）\n"
    "- 不要提及\"蜜罐\"\n"
    "- 陈述最能说明问题的事实，面无表情\n"
    "- 提到最荒谬的密码\n\n"
    "示例：\n"
    "- \"三万次 root 尝试，密码全是法国人名，破了两次，打了 ok 就走了。\"\n"
    "- \"18583 次 root 尝试，一次都没进去——一次都没有。\"\n\n"
    "用一句话描述这个攻击者：\n"
    "{profile}"
)

PROMPT_DRIVEBY = (
    "为安全仪表盘撰写一句简短、不屑一顾的描述。\n\n"
    "规则：\n"
    "- 只根据日志中实际出现的行为判断\n"
    "- 一句话，不超过 150 字符\n"
    "- 不要使用 markdown、反引号\n"
    "- 不要以\"攻击者\"开头\n"
    "- 不要提及\"蜜罐\"\n"
    "- 简短。这些不值得关注。\n\n"
    "示例：\n"
    "- \"ubuntu:ubuntu，进来了，没执行命令，走了。\"\n"
    "- \"试了 root:12345，失败，下一个。\"\n\n"
    "用一句话描述这个攻击者：\n"
    "{profile}"
)

PROMPT_PERSISTENT = (
    "你是一名蜜罐安全分析员，为仪表盘撰写一句话攻击者描述。\n"
    "风格冷峻、技术精确。聚焦在持久性上。\n\n"
    "规则：\n"
    "- 只根据日志中实际出现的行为判断，不要编造或推测\n"
    "- 一句话，不超过 200 字符\n"
    "- 不要使用 markdown、反引号\n"
    "- 不要以\"攻击者\"开头\n"
    "- 不要重复元数据\n"
    "- 不要提及\"蜜罐\"\n"
    "- 突出重复行为或耐心\n\n"
    "示例：\n"
    "- \"18 次会话，密码从 123、1234、12345 顺序试——像一个执着的幼儿园小朋友在翻字典。\"\n"
    "- \"七个会话都在跑 HONEYPOT_TEST_12345——结果答案是 yes。\"\n\n"
    "用一句话描述这个攻击者：\n"
    "{profile}"
)

_CATEGORY_PROMPTS = {
    'sophisticated': PROMPT_SOPHISTICATED,
    'recon': PROMPT_RECON,
    'bomber': PROMPT_BOMBER,
    'persistent': PROMPT_PERSISTENT,
    'driveby': PROMPT_DRIVEBY,
}

RECON_KEYWORDS = {
    'uname', '/proc/cpu', '/proc/mem', 'lscpu', 'nproc', 'hostname',
    'whoami', 'id', 'free', 'df', 'uptime', '/etc/os-release',
    '/bin/./uname',
}


def _is_mostly_recon(commands):
    """Check if >60% of commands are recon-type."""
    if not commands:
        return False
    recon_count = sum(1 for cmd in commands
                      if any(kw in cmd.lower() for kw in RECON_KEYWORDS))
    return recon_count / len(commands) > 0.6


def classify_attacker(attempt_count, session_count, command_count, unique_commands,
                      has_ssh_key, has_payload, interestingness_score):
    """Classify attacker into routing category.
    Returns: 'sophisticated', 'recon', 'bomber', 'persistent', 'driveby'"""
    if has_ssh_key or has_payload:
        return 'sophisticated'
    if interestingness_score > 20:
        return 'sophisticated'
    if command_count > 0 and _is_mostly_recon(unique_commands):
        return 'recon'
    if attempt_count > 1000 and command_count < 3:
        return 'bomber'
    if session_count > 5 and attempt_count < 5000:
        return 'persistent'
    if attempt_count < 100 and session_count <= 2:
        return 'driveby'
    return 'bomber'


def _category_fallback(category, profile_data):
    """Category-appropriate fallback when LLM fails."""
    if category == 'sophisticated':
        actions = profile_data.get('key_actions', 'recon and exploitation')
        return "Gained access and ran %s \u2014 hands-on-keyboard operator." % actions
    elif category == 'recon':
        logins = profile_data.get('login_count', 'multiple')
        return "Logged in %s times, ran the same fingerprinting commands, left." % logins
    elif category == 'bomber':
        count = profile_data.get('attempt_count', 'thousands of')
        passwords = profile_data.get('notable_passwords', '')
        if passwords:
            return "%s login attempts with passwords like %s \u2014 never got anywhere." % (count, passwords)
        return "%s login attempts, brute-forcing with a dictionary \u2014 no luck." % count
    elif category == 'persistent':
        sessions = profile_data.get('session_count', 'multiple')
        return "Kept coming back across %s sessions \u2014 persistence without payoff." % sessions
    elif category == 'driveby':
        cred = profile_data.get('top_cred', 'default creds')
        got_in = profile_data.get('got_in', False)
        if got_in:
            return "%s, in, nothing, gone." % cred
        return "Tried %s, failed, moved on." % cred
    return "Attempted access without notable activity."


def build_profile_text(ip, attempt_count, ip_sessions, all_cmds, creds):
    """Build natural-language profile summary for the LLM prompt.
    Curated to give the model the right material for each category."""
    login_count = len(ip_sessions)
    parts = ["%d attempts" % attempt_count]
    if login_count > 0:
        parts.append("%d login%s" % (login_count, 's' if login_count != 1 else ''))
    profile = ", ".join(parts) + ". "

    if all_cmds:
        unique = list(dict.fromkeys(all_cmds))
        cmd_samples = [cmd[:120] for cmd in unique[:8]]
        profile += "Commands: " + " | ".join(cmd_samples) + ". "

        cmd_str = " ".join(all_cmds).lower()
        if "authorized_keys" in cmd_str or "ssh-keygen" in cmd_str:
            profile += "SSH key injection detected. "
        if "chattr" in cmd_str:
            profile += "Used chattr for file locking. "
        if "mdrfckr" in cmd_str:
            profile += "Injected mdrfckr SSH key. "
        if re.search(r'passwd\b', cmd_str):
            profile += "Changed root password. "
        if "wget" in cmd_str or "curl" in cmd_str:
            profile += "Downloaded remote payload. "
        if re.search(r'chmod\s+(777|\+x)', cmd_str):
            profile += "Made files executable. "
        if "hosts.deny" in cmd_str:
            profile += "Cleared hosts.deny. "
        if any(x in cmd_str for x in ["xmrig", "minerd", "cpuminer"]):
            profile += "Deployed cryptominer. "
    elif login_count > 0:
        profile += "Got in but ran no commands. "

    # Notable passwords
    if creds:
        unique_creds = list(set(creds))
        exotic = [c for c in unique_creds if c not in BORING_CREDS]
        if exotic:
            passwords = []
            for c in exotic[:5]:
                sep = ":" if ":" in c else "/"
                passwords.append(c.split(sep)[-1])
            if passwords:
                profile += "Notable passwords: " + ", ".join(passwords) + ". "

        pw_list = []
        for c in creds[:20]:
            sep = ":" if ":" in c else "/"
            pw_list.append(c.split(sep)[-1])
        seq = [p for p in pw_list if p in ("123", "1234", "12345", "123456", "1234567", "12345678")]
        if len(seq) >= 3:
            profile += "Sequential passwords (123, 1234, 12345...). "

        cred_str_lower = " ".join(creds).lower()
        if any(w in cred_str_lower for w in ["solana", "validator", "raydium", "firedancer", "snarkos"]):
            profile += "Using crypto/Solana credentials. "

    if all_cmds and len(set(all_cmds)) == 1 and "echo" in all_cmds[0].lower():
        profile += "Only command: echo ok. "

    return profile.strip()


# Paths & endpoints — overridable via env for containerized deploys. The
# defaults preserve the original on-host behavior exactly (data files alongside
# the script, Cowrie logs at their fixed path, Ollama on localhost).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("HONEYPOT_DATA_DIR", SCRIPT_DIR)
LOG_PATH = os.environ.get("COWRIE_LOG_PATH", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3.5:9b")

# LLM_PROVIDER: "ollama"（默认）、"openai"（OpenAI 兼容 API）、"none"（禁用 LLM）
_LLM_VALID_PROVIDERS = {"ollama", "openai", "none"}
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").lower()
if LLM_PROVIDER not in _LLM_VALID_PROVIDERS:
    print(f"[!] Unknown LLM_PROVIDER={LLM_PROVIDER!r}, falling back to 'none'. "
          f"Valid options: {', '.join(sorted(_LLM_VALID_PROVIDERS))}")
    LLM_PROVIDER = "none"

# OpenAI 兼容 API 配置（仅 LLM_PROVIDER=openai 时生效）
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "").rstrip("/")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4.1-mini")

# 运行时实际使用的 LLM 配置（由 LLM_PROVIDER 决定）
if LLM_PROVIDER == "openai":
    LLM_API_BASE = OPENAI_BASE_URL or "https://api.openai.com/v1"
    LLM_API_KEY = OPENAI_API_KEY
    LLM_MODEL = OPENAI_MODEL
elif LLM_PROVIDER == "ollama":
    LLM_API_BASE = OLLAMA_URL + "/v1"
    LLM_API_KEY = ""
    LLM_MODEL = OLLAMA_MODEL
else:
    LLM_API_BASE = ""
    LLM_API_KEY = ""
    LLM_MODEL = ""

os.makedirs(DATA_DIR, exist_ok=True)
CACHE_PATH = os.path.join(DATA_DIR, "geoip_cache.json")
OUTPUT_PATH = os.path.join(DATA_DIR, "dashboard.html")
CACHE_FILE = os.path.join(DATA_DIR, "description_cache.json")

# Max attacker IPs plotted on the map. The map filters per-week client-side, so
# this only bounds page size; set well above the ~5–6k unique IPs in a 60-day
# window so recent weeks (newer, lower-volume IPs) aren't dropped off the map.
MAX_MAP_MARKERS = int(os.environ.get("MAX_MAP_MARKERS", "10000"))


def atomic_json_write(filepath, data, indent=2):
    """Write JSON atomically using temp file + os.rename (H3 fix)."""
    dirpath = os.path.dirname(filepath)
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dirpath, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=indent)
        os.rename(tmp_path, filepath)
    except Exception as e:
        print(f"[!] Atomic write failed for {filepath}: {e}")
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        return False
    return True


def annotate_command(cmd):
    """Layer 1: Dictionary lookup for command annotations. Returns short technical note or None."""
    cmd_stripped = cmd.strip()
    cmd_lower = cmd_stripped.lower()
    
    # Exact/prefix matches first
    annotations = {
        "uname -a": "OS/kernel identification",
        "uname": "OS identification",
        "cat /etc/passwd": "user enumeration",
        "cat /etc/shadow": "password hash extraction",
        "cat /proc/cpuinfo": "CPU profiling",
        "cat /proc/meminfo": "memory profiling",
        "cat /proc/version": "kernel version check",
        "free -m": "RAM check",
        "free -h": "RAM check",
        "free": "RAM check",
        "df -h": "disk space check",
        "df": "disk space check",
        "lscpu": "CPU architecture scan",
        "nproc": "core count check",
        "dmidecode": "hardware inventory",
        "lspci": "PCI device enumeration",
        "lsblk": "block device enumeration",
        "lsusb": "USB device scan",
        "ifconfig": "network mapping",
        "ip addr": "network mapping",
        "ip a": "network mapping",
        "ip route": "routing table check",
        "hostname": "hostname discovery",
        "hostname -I": "IP address discovery",
        "whoami": "privilege check",
        "id": "privilege check",
        "w": "logged-in users check",
        "who": "logged-in users check",
        "last": "login history check",
        "uptime": "uptime check",
        "ps aux": "process enumeration",
        "ps -ef": "process enumeration",
        "top": "process monitoring",
        "netstat -tulpn": "open ports scan",
        "ss -tulpn": "open ports scan",
        "mount": "mounted filesystem check",
        "dmesg": "kernel message dump",
        "env": "environment variable dump",
        "printenv": "environment variable dump",
        "history": "history snooping",
        "cat ~/.bash_history": "history snooping",
        "cat /root/.bash_history": "history snooping",
    }
    
    if cmd_lower in annotations:
        return annotations[cmd_lower]
    
    patterns = [
        (r'export\s+HISTFILE\s*=\s*/dev/null', "anti-forensics: disable history"),
        (r'unset\s+HISTFILE', "anti-forensics: disable history"),
        (r'export\s+HISTSIZE\s*=\s*0', "anti-forensics: disable history"),
        (r'HISTORY.*=/dev/null', "anti-forensics: disable history"),
        (r'/bin/\./\w+', "obfuscated system check"),
        (r'cat\s+/etc/passwd', "user enumeration"),
        (r'cat\s+/etc/shadow', "password hash extraction"),
        (r'cat\s+/proc/cpuinfo', "CPU profiling"),
        (r'wget\s+https?://', "payload download from C2"),
        (r'curl\s+https?://', "payload download"),
        (r'curl\s+-[sOo]', "payload download"),
        (r'tftp\s+', "payload download via TFTP"),
        (r'chmod\s+\+x', "make executable"),
        (r'chmod\s+[0-7]*7[0-7]*\s+', "make executable (world)"),
        (r'^\.\/', "execute payload"),
        (r'/tmp/\w+', "execute from /tmp"),
        (r'crontab', "persistence setup"),
        (r'/etc/cron', "persistence setup"),
        (r'iptables', "firewall tampering"),
        (r'ufw\s+', "firewall tampering"),
        (r'systemctl', "service manipulation"),
        (r'service\s+', "service manipulation"),
        (r'rm\s+-rf\s+/', "destructive wipe attempt"),
        (r'rm\s+.*\.log', "log cleanup"),
        (r'pkill|killall|kill\s+-9', "process termination"),
        (r'useradd|adduser', "create backdoor account"),
        (r'passwd\s+', "password change attempt"),
        (r'ssh-keygen|authorized_keys', "SSH key persistence"),
        (r'nc\s+-[le]|ncat|netcat', "reverse shell / listener"),
        (r'/dev/tcp/', "bash reverse shell"),
        (r'base64\s+-d|base64\s+--decode', "decode obfuscated payload"),
        (r'python.*-c.*import', "Python one-liner execution"),
        (r'perl\s+-e', "Perl one-liner execution"),
        (r'xmrig|minerd|ccminer|cpuminer', "cryptominer deployment"),
        (r'\.bash_history', "history snooping"),
        (r'history', "history snooping"),
        (r'dd\s+if=', "disk operation"),
        (r'echo\s+.*>\s*/etc/', "system file modification"),
        (r'echo\s+.*>>\s*/etc/', "system file append"),
        (r'apt\s+install|yum\s+install|pip\s+install', "package installation"),
        (r'docker\s+', "container manipulation"),
        (r'chattr\s+', "file attribute tampering"),
    ]
    
    for pattern, note in patterns:
        if re.search(pattern, cmd_lower):
            return note
    
    return None

def parse_log(path):
    """Parse Cowrie JSON log, skipping malformed lines. Handles .gz files."""
    events = []
    if not os.path.exists(path):
        print(f"[!] Log file not found: {path}")
        return events
    # Detect gzip by magic bytes, not extension
    is_gzip = False
    try:
        with open(path, "rb") as f:
            is_gzip = f.read(2) == b'\x1f\x8b'
    except Exception:
        pass
    opener = gzip.open if is_gzip else open
    try:
        with opener(path, "rt") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"[!] Skipping malformed JSON at line {lineno}")
    except Exception as e:
        print(f"[!] Error reading {path}: {e}")
    return events


def load_geo_cache():
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r") as f:
                cache = json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
        # Prune entries older than 30 days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        pruned = {}
        for k, v in cache.items():
            if isinstance(v, dict) and "_cached_at" in v:
                if v["_cached_at"] > cutoff:
                    pruned[k] = v
            else:
                pruned[k] = v
        if len(pruned) < len(cache):
            print(f"[*] Pruned {len(cache) - len(pruned)} stale geoip cache entries")
        return pruned
    return {}


def save_geo_cache(cache):
    """Save geo cache atomically (H3 fix)."""
    now = datetime.now(timezone.utc).isoformat()
    for k, v in cache.items():
        if isinstance(v, dict) and "_cached_at" not in v:
            v["_cached_at"] = now
    atomic_json_write(CACHE_PATH, cache)


def batch_geoip_lookup(ips, cache):
    """Lookup IPs via ip-api.com batch endpoint (max 100 per request)."""
    to_lookup = [ip for ip in ips if ip not in cache or (isinstance(cache.get(ip), dict) and cache[ip].get("country") == "Unknown")]
    if not to_lookup:
        return cache

    for i in range(0, len(to_lookup), 100):
        batch = to_lookup[i:i+100]
        print(f"[*] GeoIP batch lookup: {len(batch)} IPs...")
        payload = json.dumps([{"query": ip, "fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,query"} for ip in batch]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                results = json.loads(resp.read().decode())
                for r in results:
                    ip = r.get("query", "")
                    if r.get("status") == "success":
                        cache[ip] = {
                            "country": r.get("country", "Unknown"),
                            "countryCode": r.get("countryCode", ""),
                            "region": r.get("regionName", ""),
                            "city": r.get("city", ""),
                            "lat": r.get("lat", 0),
                            "lon": r.get("lon", 0),
                            "isp": r.get("isp", "Unknown"),
                            "org": r.get("org", "")
                        }
                    else:
                        cache[ip] = {
                            "country": "Unknown", "countryCode": "", "region": "",
                            "city": "", "lat": 0, "lon": 0, "isp": "Unknown", "org": ""
                        }
        except (urllib.error.URLError, urllib.error.HTTPError, Exception) as e:
            print(f"[!] Batch GeoIP lookup failed: {e}")
            for ip in batch:
                if ip not in cache:
                    cache[ip] = {
                        "country": "Unknown", "countryCode": "", "region": "",
                        "city": "", "lat": 0, "lon": 0, "isp": "Unknown", "org": ""
                    }
        if i + 100 < len(to_lookup):
            time.sleep(1)

    save_geo_cache(cache)
    return cache


def flag_emoji(cc):
    if not cc or len(cc) != 2:
        return "\U0001f3f4"
    return chr(0x1F1E6 + ord(cc[0].upper()) - ord('A')) + chr(0x1F1E6 + ord(cc[1].upper()) - ord('A'))


COUNTRY_FLAVORS = {
    "NL": ["tulip", "windmill", "gouda", "bike", "stroopwafel", "clog", "dutch"],
    "US": ["eagle", "burger", "yankee", "cowboy", "liberty", "star"],
    "CN": ["dragon", "panda", "jade", "silk", "lantern", "wok"],
    "RU": ["bear", "frost", "cosmo", "steppe", "borscht", "tsar"],
    "BR": ["samba", "toucan", "carnival", "capoeira", "acai"],
    "IN": ["chai", "tiger", "monsoon", "spice", "lotus"],
    "DE": ["pretzel", "stein", "autobahn", "blitz", "strudel"],
    "FR": ["baguette", "crepe", "chateau", "bistro", "monet"],
    "KR": ["kimchi", "hanbok", "k-pop", "bibimbap", "seoul"],
    "JP": ["sakura", "ramen", "sensei", "shogun", "bonsai"],
    "GB": ["crumpet", "tea", "fog", "beefeater", "scone"],
    "MY": ["durian", "batik", "satay", "kite", "nasi"],
    "AU": ["kiwi", "outback", "roo", "barbie", "reef"],
    "CA": ["maple", "moose", "poutine", "hockey", "toque"],
    "SE": ["viking", "fjord", "meatball", "abba", "fika"],
    "VN": ["pho", "lotus", "mekong", "bamboo", "dragonfruit"],
    "ID": ["komodo", "batik", "rendang", "volcano", "garuda"],
    "TR": ["sultan", "bazaar", "kebab", "bosphorus", "anatolia"],
    "IR": ["saffron", "persia", "cyrus", "rosewater", "pistachio"],
    "UA": ["cossack", "sunflower", "steppe", "trident", "varenyk"],
    "PL": ["pierogi", "bison", "amber", "falcon", "zubr"],
    "RO": ["dracula", "carpath", "mamaliga", "danube", "lynx"],
    "ES": ["flamenco", "siesta", "paella", "matador", "rioja"],
    "IT": ["pasta", "vespa", "espresso", "gondola", "ciao"],
    "MX": ["taco", "lucha", "agave", "cactus", "mariachi"],
    "AR": ["tango", "pampas", "gaucho", "mate", "asado"],
    "ZA": ["springbok", "savanna", "braai", "kudu", "rooibos"],
    "EG": ["sphinx", "nile", "pharaoh", "scarab", "papyrus"],
    "SG": ["merlion", "orchid", "kopi", "durian", "hawker"],
    "TH": ["padthai", "elephant", "muay", "mango", "tuktuk"],
    "PH": ["jeepney", "adobo", "tarsier", "bayan", "halohalo"],
    "TW": ["boba", "taipei", "oolong", "ximen", "betel"],
    "HK": ["dimsum", "harbor", "junk", "neon", "peak"],
    "AE": ["dune", "falcon", "oasis", "souk", "dhow"],
    "SA": ["oryx", "date", "oasis", "najd", "frankincense"],
    "NG": ["jollof", "afrobeat", "naija", "delta", "nok"],
    "PK": ["indus", "markhor", "minar", "truck", "chinar"],
    "BD": ["delta", "jute", "rickshaw", "ilish", "sundarban"],
    "VE": ["arepa", "orinoco", "angel", "llanero", "harpy"],
}
DEFAULT_FLAVORS = ["ghost", "shadow", "phantom", "specter", "wraith", "cipher",
                   "rogue", "nomad", "drifter", "void", "echo", "static", "husk"]

# Adjective pool — paired with a country-flavored noun so nicknames draw from a
# large, characterful namespace (far fewer collisions than the old single word).
NICKNAME_ADJECTIVES = [
    "rusty", "silent", "feral", "grumpy", "sneaky", "brazen", "weary", "manic",
    "stoic", "jittery", "crimson", "obsidian", "vapor", "glitchy", "midnight",
    "rabid", "listless", "clandestine", "baroque", "derelict", "frantic", "sullen",
    "arctic", "molten", "spectral", "unhinged", "velvet", "ashen", "wired", "rogue",
    "cryptic", "drowsy", "savage", "placid", "gnarled", "hollow", "brisk", "murky",
    "zealous", "aloof", "lurking", "restless", "venomous", "wily", "scrappy",
    "ironclad", "nocturnal", "haywire",
]

BORING_CREDS = {
    "root:root", "admin:admin", "admin:password", "admin:123456", "root:123456",
    "user:user", "test:test", "admin:admin123", "root:password", "admin:1234",
    "root:1234", "root:admin", "guest:guest", "admin:12345", "root:12345",
    "root:toor", "admin:admin1", "root:root123", "admin:default", "root:default",
    "ubuntu:ubuntu", "user:password", "test:123456", "admin:1q2w3e4r", "root:1q2w3e4r",
    "support:support", "user:123456", "pi:raspberry", "admin:pass", "root:pass",
    "admin:123", "root:123", "test:test123", "root:1234567890", "admin:1234567890",
}

_nickname_cache = {}
_nickname_counter = Counter()

def _ip_hash(ip):
    """Stable per-IP hash. Uses md5 rather than the builtin hash() (which is
    salted per process), so an attacker keeps the same nickname across runs."""
    return int(hashlib.md5(ip.encode("utf-8")).hexdigest(), 16)


def _behavior_suffix(creds_tried):
    """Behavioral tag derived from the credentials an IP tried."""
    if not creds_tried:
        return ""
    cred_str = " ".join(creds_tried[:100]).lower()
    if any(w in cred_str for w in ["solana", "sol", "validator", "raydium", "firedancer"]):
        return "_sol"
    if any(w in cred_str for w in ["root", "admin", "ubuntu"]):
        return "_root"
    if any(w in cred_str for w in ["postgres", "mysql", "oracle", "mongo"]):
        return "_db"
    if any(w in cred_str for w in ["pi", "raspberry"]):
        return "_pi"
    if any(w in cred_str for w in ["miner", "eth", "bitcoin"]):
        return "_crypto"
    return ""


def generate_nickname(ip, geo, creds_tried=None):
    """Deterministic, characterful nickname: <adjective>_<country-noun>[_behavior]
    (e.g. 'sullen_tulip_sol'). Seeded from a stable hash of the IP, so the same
    attacker always renders the same name."""
    if ip in _nickname_cache:
        return _nickname_cache[ip]

    cc = geo.get("countryCode", "").upper()
    nouns = COUNTRY_FLAVORS.get(cc, DEFAULT_FLAVORS)
    h = _ip_hash(ip)
    adj = NICKNAME_ADJECTIVES[(h >> 16) % len(NICKNAME_ADJECTIVES)]
    noun = nouns[h % len(nouns)]
    base = f"{adj}_{noun}{_behavior_suffix(creds_tried)}"

    # Deterministic collision handling: a second, distinct IP that lands on the
    # same base gets a stable discriminator from its own address (final IPv4
    # octet / IPv6 segment), never an order-dependent counter.
    _nickname_counter[base] += 1
    if _nickname_counter[base] > 1:
        tail = ip.split(":")[-1].split(".")[-1] or str(h % 1000)
        nickname = f"{base}_{tail}"
    else:
        nickname = base

    _nickname_cache[ip] = nickname
    return nickname


def load_cache():
    """Load description cache. Good descriptions are permanent — no expiry."""
    try:
        with open(CACHE_FILE, "r") as f:
            cache = json.load(f)
    except (json.JSONDecodeError, IOError, OSError):
        return {}
    return cache

def _cache_get(cache, key):
    """Get value from cache, handling both old (string) and new (dict with text) formats."""
    v = cache.get(key)
    if v is None:
        return None
    if isinstance(v, dict):
        text = v.get("text", v.get("story", ""))
    else:
        text = v
    # Always strip markdown from cached values on read
    return strip_markdown(text) if text else text

def save_cache(cache):
    """Save description cache atomically (H3 fix)."""
    now = datetime.now(timezone.utc).isoformat()
    out = {}
    for k, v in cache.items():
        if isinstance(v, str):
            out[k] = {"text": v, "_cached_at": now}
        elif isinstance(v, dict) and "_cached_at" not in v:
            v["_cached_at"] = now
            out[k] = v
        else:
            out[k] = v
    atomic_json_write(CACHE_FILE, out)


def analyze_events(events, geo_cache):
    """Extract all stats from parsed events."""
    stats = {
        "total_sessions": 0,
        "total_login_attempts": 0,
        "successful_logins": 0,
        "unique_ips": set(),
        "commands_executed": 0,
        "files_downloaded": 0,
    }

    ip_attempts = Counter()
    ip_first_seen = {}
    ip_last_seen = {}
    ip_creds = defaultdict(list)
    cred_combos = Counter()
    timeline = Counter()
    recent_events = []
    successful_sessions = defaultdict(list)
    session_ips = {}
    session_success = set()
    session_creds = {}

    hourly_attempts = Counter()
    daily_sessions = Counter()
    daily_login_attempts = Counter()
    daily_successful = Counter()
    daily_ips = defaultdict(set)
    daily_commands = Counter()
    daily_ip_attempts = defaultdict(Counter)
    all_timestamps = []

    for e in events:
        eid = e.get("eventid", "")
        ip = e.get("src_ip", "")
        ts = e.get("timestamp", "")
        session = e.get("session", "")

        if ip:
            stats["unique_ips"].add(ip)
        if session and ip:
            session_ips[session] = ip

        if ts:
            try:
                dt_est = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(LOCAL_TZ)
                day_key = dt_est.strftime("%Y-%m-%d")
                all_timestamps.append(dt_est)
            except (ValueError, AttributeError):
                day_key = None
        else:
            day_key = None

        if eid == "cowrie.session.connect":
            stats["total_sessions"] += 1
            if day_key:
                daily_sessions[day_key] += 1
                if ip:
                    daily_ips[day_key].add(ip)

        elif eid == "cowrie.login.failed":
            stats["total_login_attempts"] += 1
            ip_attempts[ip] += 1
            if ip not in ip_first_seen or ts < ip_first_seen[ip]:
                ip_first_seen[ip] = ts
            if ip not in ip_last_seen or ts > ip_last_seen[ip]:
                ip_last_seen[ip] = ts
            u = e.get("username", "")
            p = e.get("password", "")
            combo = f"{h(u)}:{h(p)}"
            ip_creds[ip].append(combo)
            cred_combos[combo] += 1
            if day_key:
                daily_login_attempts[day_key] += 1
                if ip:
                    daily_ips[day_key].add(ip)
                    daily_ip_attempts[day_key][ip] += 1
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                dt_local = dt.astimezone(LOCAL_TZ)
                bucket = dt_local.strftime("%Y-%m-%d %H:00 ") + dt_local.strftime("%Z")
                timeline[bucket] += 1
                hourly_attempts[dt_local.hour] += 1
            except (ValueError, AttributeError):
                pass
            key_type = e.get("type", "")
            if key_type and not p:
                action = f"{LOCALE['key_auth']}: {h(u)} ({h(key_type)})"
            else:
                action = f"{LOCALE['login_attempt']}: {h(u)}/{h(p)}"
            recent_events.append({"ts": ts, "ip": ip, "action": action})

        elif eid == "cowrie.login.success":
            stats["total_login_attempts"] += 1
            stats["successful_logins"] += 1
            ip_attempts[ip] += 1
            if ip not in ip_first_seen or ts < ip_first_seen[ip]:
                ip_first_seen[ip] = ts
            if ip not in ip_last_seen or ts > ip_last_seen[ip]:
                ip_last_seen[ip] = ts
            u = e.get("username", "")
            p = e.get("password", "")
            combo = f"{h(u)}:{h(p)}"
            ip_creds[ip].append(combo)
            cred_combos[combo] += 1
            session_success.add(session)
            session_creds[session] = f"{h(u)}/{h(p)}"
            if day_key:
                daily_login_attempts[day_key] += 1
                daily_successful[day_key] += 1
                if ip:
                    daily_ips[day_key].add(ip)
                    daily_ip_attempts[day_key][ip] += 1
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                dt_local = dt.astimezone(LOCAL_TZ)
                bucket = dt_local.strftime("%Y-%m-%d %H:00 ") + dt_local.strftime("%Z")
                timeline[bucket] += 1
                hourly_attempts[dt_local.hour] += 1
            except (ValueError, AttributeError):
                pass
            recent_events.append({"ts": ts, "ip": ip, "action": f"{LOCALE['login_success']}: {h(u)}/{h(p)}"})

        elif eid == "cowrie.command.input":
            stats["commands_executed"] += 1
            cmd = e.get("input", "")
            if session in session_success:
                successful_sessions[session].append({"ts": ts, "cmd": cmd})
            recent_events.append({"ts": ts, "ip": ip, "action": f"{LOCALE['command_prefix']} {h(cmd)}"})
            if day_key:
                daily_commands[day_key] += 1

        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            stats["files_downloaded"] += 1
            url = e.get("url", e.get("filename", "?"))
            recent_events.append({"ts": ts, "ip": ip, "action": f"{LOCALE['file_prefix']} {h(url)}"})

    stats["unique_ips"] = len(stats["unique_ips"])

    sorted_timeline = sorted(timeline.items())
    timeline_labels = [t[0] for t in sorted_timeline]
    timeline_data = [t[1] for t in sorted_timeline]

    top_attackers = []
    for ip, count in ip_attempts.most_common(10):
        geo = geo_cache.get(ip, {})
        nickname = generate_nickname(ip, geo, ip_creds.get(ip, []))
        top_attackers.append({
            "ip": ip,
            "count": count,
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", ""),
            "cc": geo.get("countryCode", ""),
            "flag": flag_emoji(geo.get("countryCode", "")),
            "isp": geo.get("isp", "Unknown"),
            "nickname": nickname,
        })

    top_creds = cred_combos.most_common(20)
    # Take last 100 events, then group consecutive same-IP same-action-type
    raw_recent = recent_events[-100:]
    grouped_recent = []
    for ev in raw_recent:
        action_type = ev["action"].split(":")[0]
        grp_key = (ev["ip"], action_type)
        if grouped_recent and grouped_recent[-1]["_group_key"] == grp_key:
            grouped_recent[-1]["count"] += 1
            grouped_recent[-1]["last_ts"] = ev["ts"]
        else:
            grouped_recent.append({**ev, "_group_key": grp_key, "count": 1,
                                   "first_ts": ev["ts"], "last_ts": ev["ts"]})
    recent_events = grouped_recent[-20:]

    markers = []
    seen_ips = set()
    # Plot every geolocated attacker, not just the top-500 by total attempts.
    # That old cap biased the map toward long-lived high-volume IPs, so recent
    # weeks — dominated by newer, lower-volume attackers — rendered sparse or
    # empty. MAX_MAP_MARKERS is just a generous safety bound on page size.
    for ip, count in ip_attempts.most_common(MAX_MAP_MARKERS):
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        geo = geo_cache.get(ip, {})
        lat = geo.get("lat", 0)
        lon = geo.get("lon", 0)
        if lat == 0 and lon == 0:
            continue
        creds_tried = list(set(ip_creds.get(ip, [])))[:10]
        nickname = generate_nickname(ip, geo, ip_creds.get(ip, []))
        # Build per-day counts for this IP
        ip_daily = {}
        for day_k, day_counter in daily_ip_attempts.items():
            if ip in day_counter:
                ip_daily[day_k] = day_counter[ip]
        markers.append({
            "ip": ip,
            "lat": lat,
            "lon": lon,
            "count": count,
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", ""),
            "isp": geo.get("isp", "Unknown"),
            "creds": creds_tried,
            "nickname": nickname,
            "first_seen": ip_first_seen.get(ip, ""),
            "last_seen": ip_last_seen.get(ip, ""),
            "daily_counts": ip_daily,
        })

    for ip in list(set(session_ips.values())):
        if ip not in seen_ips:
            geo = geo_cache.get(ip, {})
            lat = geo.get("lat", 0)
            lon = geo.get("lon", 0)
            if lat != 0 or lon != 0:
                markers.append({
                    "ip": ip, "lat": lat, "lon": lon, "count": 0,
                    "country": geo.get("country", "Unknown"),
                    "isp": geo.get("isp", "Unknown"),
                    "creds": [],
                })

    coord_counts = Counter((round(m["lat"], 1), round(m["lon"], 1)) for m in markers)
    coord_indices = {}
    for m in markers:
        key = (round(m["lat"], 1), round(m["lon"], 1))
        total = coord_counts[key]
        if total > 1:
            idx = coord_indices.get(key, 0)
            coord_indices[key] = idx + 1
            angle = (2 * math.pi * idx) / total
            spread = 0.04 * min(total, 5)
            m["lat"] += math.sin(angle) * spread
            m["lon"] += math.cos(angle) * spread

    success_data = []
    for sid, cmds in successful_sessions.items():
        ip = session_ips.get(sid, "?")
        success_data.append({"session": sid, "ip": ip, "commands": cmds, "creds": session_creds.get(sid, "unknown")})
    success_data.sort(key=lambda s: s["commands"][0]["ts"] if s["commands"] else "", reverse=True)

    today_est = datetime.now(LOCAL_TZ).strftime("%Y-%m-%d")
    all_days = sorted(set(
        list(daily_sessions.keys()) + list(daily_login_attempts.keys()) +
        list(daily_commands.keys())
    ), reverse=True)

    daily_breakdown = []
    for day in all_days:
        top_ip = ""
        top_nick = ""
        if daily_ip_attempts[day]:
            top_ip = daily_ip_attempts[day].most_common(1)[0][0]
            geo = geo_cache.get(top_ip, {})
            top_nick = generate_nickname(top_ip, geo, ip_creds.get(top_ip, []))
        daily_breakdown.append({
            "date": day,
            "sessions": daily_sessions.get(day, 0),
            "login_attempts": daily_login_attempts.get(day, 0),
            "successful": daily_successful.get(day, 0),
            "unique_ips": len(daily_ips.get(day, set())),
            "commands": daily_commands.get(day, 0),
            "top_attacker_ip": top_ip,
            "top_attacker_nick": top_nick,
        })

    today_stats = {
        "sessions": daily_sessions.get(today_est, 0),
        "login_attempts": daily_login_attempts.get(today_est, 0),
        "successful_logins": daily_successful.get(today_est, 0),
        "unique_ips": len(daily_ips.get(today_est, set())),
        "commands": daily_commands.get(today_est, 0),
    }

    if all_timestamps:
        first_event = min(all_timestamps)
        days_active = max(1, (datetime.now(LOCAL_TZ) - first_event).days + 1)
    else:
        days_active = 0
    attacks_per_day = round(stats["total_login_attempts"] / max(1, days_active), 1)
    d = max(1, days_active)
    averages = {
        "sessions_per_day": round(stats["total_sessions"] / d, 1),
        "logins_per_day": attacks_per_day,
        "successful_per_day": round(stats["successful_logins"] / d, 1),
        "ips_per_day": round(stats["unique_ips"] / d, 1),
        "commands_per_day": round(stats["commands_executed"] / d, 1),
        "success_rate": round(stats["successful_logins"] / max(1, stats["total_login_attempts"]) * 100, 1),
    }

    # Compute fun all-time stats
    unique_countries = set()
    for ip_key in ip_attempts:
        geo = geo_cache.get(ip_key, {})
        cc = geo.get("country", "Unknown")
        if cc != "Unknown":
            unique_countries.add(cc)

    busiest_day = max(daily_login_attempts.items(), key=lambda x: x[1]) if daily_login_attempts else ("", 0)
    peak_hour = max(hourly_attempts.items(), key=lambda x: x[1])[0] if hourly_attempts else 0
    peak_hour_str = f"{peak_hour:02d}:00–{(peak_hour+1)%24:02d}:00"

    # Compute last 24h stats
    now_utc = datetime.now(timezone.utc)
    cutoff_24h = now_utc - timedelta(hours=24)
    last_24h = {
        "sessions": 0,
        "login_attempts": 0,
        "successful_logins": 0,
        "unique_ips": set(),
        "commands": 0,
    }
    for e in events:
        ts = e.get("timestamp", "")
        if not ts:
            continue
        try:
            evt_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        if evt_dt < cutoff_24h:
            continue
        eid = e.get("eventid", "")
        ip = e.get("src_ip", "")
        if eid == "cowrie.session.connect":
            last_24h["sessions"] += 1
            if ip:
                last_24h["unique_ips"].add(ip)
        elif eid == "cowrie.login.failed":
            last_24h["login_attempts"] += 1
            if ip:
                last_24h["unique_ips"].add(ip)
        elif eid == "cowrie.login.success":
            last_24h["login_attempts"] += 1
            last_24h["successful_logins"] += 1
            if ip:
                last_24h["unique_ips"].add(ip)
        elif eid == "cowrie.command.input":
            last_24h["commands"] += 1
    last_24h["unique_ips"] = len(last_24h["unique_ips"])

    # Compute peak day for each metric
    def _peak(daily_counter):
        if not daily_counter:
            return (0, "—")
        day, val = max(daily_counter.items(), key=lambda x: x[1])
        try:
            dt = datetime.strptime(day, "%Y-%m-%d")
            short = dt.strftime("%b %-d")
        except (ValueError, AttributeError):
            short = day[5:]
        return (val, short)

    peak_sessions = _peak(daily_sessions)
    peak_logins = _peak(daily_login_attempts)
    peak_successful = _peak(daily_successful)
    peak_commands = _peak(daily_commands)
    # Peak unique IPs per day
    daily_unique_ip_counts = {day: len(ips) for day, ips in daily_ips.items()}
    peak_ips = _peak(daily_unique_ip_counts)

    # Peak daily success rate
    daily_success_rates = {}
    for day in daily_login_attempts:
        attempts = daily_login_attempts[day]
        if attempts > 0:
            rate = daily_successful.get(day, 0) / attempts * 100
            daily_success_rates[day] = round(rate, 1)
    if daily_success_rates:
        peak_sr_day = max(daily_success_rates, key=daily_success_rates.get)
        peak_sr_val = daily_success_rates[peak_sr_day]
        try:
            dt = datetime.strptime(peak_sr_day, "%Y-%m-%d")
            peak_sr_short = dt.strftime("%b %-d")
        except (ValueError, AttributeError):
            peak_sr_short = peak_sr_day[5:]
        peak_success_rate = (peak_sr_val, peak_sr_short)
    else:
        peak_success_rate = (0, "—")

    return {
        "stats": stats,
        "today_stats": today_stats,
        "days_active": days_active,
        "attacks_per_day": attacks_per_day,
        "averages": averages,
        "daily_breakdown": daily_breakdown,
        "top_attackers": top_attackers,
        "top_creds": top_creds,
        "timeline_labels": timeline_labels,
        "timeline_data": timeline_data,
        "recent_events": recent_events,
        "markers": markers,
        "successful_sessions": success_data,
        "geo_cache": geo_cache,
        "ip_creds": dict(ip_creds),
        "ip_first_seen": ip_first_seen,
        "ip_last_seen": ip_last_seen,
        "unique_countries": len(unique_countries),
        "busiest_day": busiest_day,
        "peak_hour": peak_hour_str,
        "last_24h": last_24h,
        "peak_sessions": peak_sessions,
        "peak_logins": peak_logins,
        "peak_successful": peak_successful,
        "peak_commands": peak_commands,
        "peak_ips": peak_ips,
        "peak_success_rate": peak_success_rate,
        "generated": datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %Z"),
    }


def llm_healthy():
    """Quick check if LLM API is responding."""
    if LLM_PROVIDER == "none":
        return False
    try:
        if LLM_PROVIDER == "ollama":
            url = f"{OLLAMA_URL}/api/tags"
        else:
            url = f"{LLM_API_BASE}/models"
        req = urllib.request.Request(url, method="GET")
        if LLM_API_KEY:
            req.add_header("Authorization", f"Bearer {LLM_API_KEY}")
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status == 200
    except Exception:
        return False


_llm_is_healthy = None

def _check_llm_once():
    global _llm_is_healthy
    if _llm_is_healthy is None:
        if LLM_PROVIDER == "none":
            _llm_is_healthy = False
            print("[*] LLM disabled (LLM_PROVIDER=none), skipping LLM descriptions")
        else:
            _llm_is_healthy = llm_healthy()
            if not _llm_is_healthy:
                print(f"[!] LLM API not responding (provider={LLM_PROVIDER}), skipping LLM descriptions this run")
    return _llm_is_healthy


def llm_generate(prompt, model=None, temperature=0.5, max_tokens=30):
    """Call LLM via configured provider. Falls back to empty string on failure."""
    if not _check_llm_once():
        return ""
    try:
        if LLM_PROVIDER == "ollama":
            # Ollama 原生 API 格式
            payload = json.dumps({
                "model": model or OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "think": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                    "num_ctx": 512,
                    "stop": ["\n"],
                },
            }).encode()
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            resp = urllib.request.urlopen(req, timeout=300)
            return json.loads(resp.read()).get("response", "").strip()
        elif LLM_PROVIDER == "openai":
            # OpenAI 兼容 API 格式
            payload = json.dumps({
                "model": model or LLM_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": False,
            }).encode()
            req = urllib.request.Request(
                f"{LLM_API_BASE}/chat/completions",
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            if LLM_API_KEY:
                req.add_header("Authorization", f"Bearer {LLM_API_KEY}")
            resp = urllib.request.urlopen(req, timeout=300)
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"].strip()
        else:
            return ""
    except Exception as e:
        print(f"[!] LLM generation failed: {e}")
        return ""


def compute_interestingness(ip, attempt_count, data):
    """Score an attacker's interestingness for greatest hits ranking.
    Prioritizes command diversity and sophistication over raw volume."""
    score = 0.0

    # Base score from attempts (log scale, diminishing returns)
    score += min(math.log2(max(attempt_count, 1) + 1) * 2, 15)

    # Find sessions for this IP
    ip_sessions = [s for s in data.get("successful_sessions", []) if s["ip"] == ip]
    all_cmds = []
    for s in ip_sessions:
        all_cmds.extend([c["cmd"] for c in s["commands"]])

    # Big bonus for having commands at all
    if all_cmds:
        score += 20

    # Bonus for command count and diversity
    unique_cmds = set(all_cmds)
    score += min(len(unique_cmds) * 3, 30)
    score += min(len(all_cmds) * 0.5, 10)

    # Bonus for multiple sessions
    if len(ip_sessions) > 1:
        score += min(len(ip_sessions) * 2, 10)

    # Bonus for sophisticated attack patterns
    cmd_str = " ".join(all_cmds).lower()
    sophisticated_patterns = [
        ("authorized_keys", 15, "SSH key injection"),
        ("ssh-keygen", 12, "SSH key generation"),
        ("chattr", 10, "file attribute tampering"),
        ("crontab", 10, "persistence via cron"),
        ("/etc/cron", 10, "persistence via cron"),
        ("wget", 8, "payload download"),
        ("curl", 8, "payload download"),
        ("base64", 10, "obfuscated payload"),
        ("nc -", 12, "reverse shell"),
        ("/dev/tcp/", 12, "bash reverse shell"),
        ("iptables", 8, "firewall tampering"),
        ("useradd", 10, "backdoor account"),
        ("xmrig", 10, "cryptominer"),
        ("docker", 8, "container manipulation"),
        ("dmidecode", 5, "hardware profiling"),
        ("lspci", 5, "hardware profiling"),
    ]
    for pattern, bonus, _ in sophisticated_patterns:
        if pattern in cmd_str:
            score += bonus

    # Penalty for generic-only credentials
    creds = data.get("ip_creds", {}).get(ip, [])
    if creds and not all_cmds:
        boring_count = sum(1 for c in creds if c in BORING_CREDS)
        if boring_count == len(creds):
            score -= 5  # All boring creds, no commands = not interesting

    return score


def generate_greatest_hits(data, desc_cache=None):
    """Generate attacker stories using prompt routing system.
    Each attacker is classified and gets a category-specific prompt.
    Pike <pike@brezgis.com> 2026-03-22
    H1/H3 fix: accepts shared desc_cache from caller; if None, loads own copy."""
    hits = []
    geo_cache = data.get("geo_cache", {})
    ip_creds = data.get("ip_creds", {})
    _owns_cache = desc_cache is None
    if _owns_cache:
        desc_cache = load_cache()

    scored_attackers = []
    for attacker in data["top_attackers"]:
        score = compute_interestingness(attacker["ip"], attacker["count"], data)
        scored_attackers.append((score, attacker))
    scored_attackers.sort(key=lambda x: x[0], reverse=True)
    ranked_attackers = [a for _, a in scored_attackers[:6]]

    for attacker in ranked_attackers:
        nick = attacker["nickname"]
        ip = attacker["ip"]
        count = attacker["count"]
        country = attacker.get("country", "Unknown")

        ip_sessions = [s for s in data.get("successful_sessions", []) if s["ip"] == ip]
        all_cmds = []
        for s in ip_sessions:
            all_cmds.extend([c["cmd"] for c in s["commands"]])

        creds = ip_creds.get(ip, [])
        unique_cmds = list(set(all_cmds))

        # Detect attack patterns
        cmd_str_lower = " ".join(all_cmds).lower() if all_cmds else ""
        has_ssh_key = "authorized_keys" in cmd_str_lower or "ssh-keygen" in cmd_str_lower
        has_payload = bool(re.search(r'(wget|curl)\s+https?://', cmd_str_lower)) or \
                      ("chmod" in cmd_str_lower and ("777" in cmd_str_lower or "+x" in cmd_str_lower))
        int_score = compute_interestingness(ip, count, data)

        total_sessions = max(len(ip_sessions), 1)
        first_seen = data.get("ip_first_seen", {}).get(ip, "")
        last_seen = data.get("ip_last_seen", {}).get(ip, "")

        category = classify_attacker(
            attempt_count=count,
            session_count=total_sessions,
            command_count=len(all_cmds),
            unique_commands=unique_cmds,
            has_ssh_key=has_ssh_key,
            has_payload=has_payload,
            interestingness_score=int_score
        )
        print(f"[*] {nick} ({ip}): category={category}, attempts={count}, cmds={len(all_cmds)}, score={int_score:.1f}")

        # Cache check — good descriptions are permanent
        cmd_hash = hashlib.md5(str(sorted(set(all_cmds))).encode()).hexdigest()[:8] if all_cmds else "nocmds"
        cache_key = f"gh_{ip}_{cmd_hash}"

        cached_story = _cache_get(desc_cache, cache_key) if cache_key in desc_cache else None
        story = None

        if cached_story:
            is_valid, _reason = validate_llm_output(cached_story, max_chars=200)
            if is_valid and '**' not in cached_story and not any(
                cached_story.lower().startswith(p) for p in ["attacker:", "the attacker", "based on"]
            ):
                story = cached_story
                print(f"    Using cached description (valid)")
            else:
                print(f"    Cached description failed validation ({_reason}), regenerating")
                del desc_cache[cache_key]

        if story is None:
            profile_text = build_profile_text(ip, count, ip_sessions, all_cmds, creds)
            prompt_template = _CATEGORY_PROMPTS.get(category, PROMPT_BOMBER)
            prompt = prompt_template.replace("{profile}", profile_text)

            print(f"    Generating with {category} prompt...")
            raw = llm_generate(prompt, temperature=0.6, max_tokens=60)
            story = strip_markdown(raw)
            story = re.sub(r'^[\u2192\u279c>]+\s*', '', story).strip()

            # Quality gate — _bad_starts now consolidated into _BAD_PREFIXES (M1 fix)
            is_valid, reason = validate_llm_output(story, max_chars=200)
            if not is_valid:
                print(f"    First attempt failed ({reason}), retrying...")
                raw = llm_generate(prompt, temperature=0.4, max_tokens=60)
                story = strip_markdown(raw)
                story = re.sub(r'^[\u2192\u279c>]+\s*', '', story).strip()
                is_valid, reason = validate_llm_output(story, max_chars=200)

            if not is_valid:
                print(f"    LLM failed twice, using {category} fallback")
                exotic_pws = [c for c in set(creds) if c not in BORING_CREDS]
                pw_samples = []
                for c in exotic_pws[:3]:
                    sep = ":" if ":" in c else "/"
                    pw_samples.append(c.split(sep)[-1])

                fallback_data = {
                    'attempt_count': count,
                    'session_count': total_sessions,
                    'login_count': len(ip_sessions),
                    'key_actions': ', '.join(unique_cmds[:5]) if unique_cmds else 'recon',
                    'notable_passwords': ', '.join(pw_samples) if pw_samples else '',
                    'top_cred': creds[0] if creds else 'default creds',
                    'got_in': len(ip_sessions) > 0,
                }
                story = _category_fallback(category, fallback_data)

            if story:
                desc_cache[cache_key] = story
                print(f"    Cached: {story[:80]}...")

        # Final cleanup
        if story:
            for prefix in [f"Nickname: {nick}", f"{nick}:", f'"{nick}"', f"**{nick}**"]:
                if story.lower().startswith(prefix.lower()):
                    story = story[len(prefix):].lstrip(" -:,")
            if " Or:" in story or " Or," in story:
                story = story.split(" Or:")[0].split(" Or,")[0].strip()
            story = story.strip('"').strip()
            if len(story) > 200:
                story = story[:197].rsplit(" ", 1)[0] + "..."

        if not story:
            if all_cmds:
                story = f"Gained access and executed {len(all_cmds)} commands."
            else:
                story = f"Attempted {count} logins without gaining access."

        # Time range
        time_range = ""
        if first_seen and last_seen:
            try:
                f_utc = datetime.fromisoformat(first_seen.replace("Z", "+00:00")[:26]).replace(tzinfo=timezone.utc)
                l_utc = datetime.fromisoformat(last_seen.replace("Z", "+00:00")[:26]).replace(tzinfo=timezone.utc)
                f_local = f_utc.astimezone(ZoneInfo("America/New_York"))
                l_local = l_utc.astimezone(ZoneInfo("America/New_York"))
                f_short = f_local.strftime("%H:%M")
                l_short = l_local.strftime("%H:%M")
                f_date = f_local.strftime("%Y-%m-%d")
                l_date = l_local.strftime("%Y-%m-%d")
                if f_date == l_date:
                    time_range = f"{f_short}\u2013{l_short}"
                else:
                    time_range = f"{f_date[5:]} {f_short} \u2013 {l_date[5:]} {l_short}"
            except (ValueError, TypeError):
                time_range = ""

        hits.append({
            "nick": nick,
            "ip": ip,
            "count": count,
            "flag": attacker.get("flag", "\U0001f3f4"),
            "story": story,
            "cmds": len(all_cmds),
            "sessions": len(ip_sessions),
            "time_range": time_range,
        })

    if _owns_cache:
        save_cache(desc_cache)
    return hits


# H2 fix: classify_commands_fast removed — dead code, superseded by the
# classify_attacker + _CATEGORY_PROMPTS prompt routing system (Bea review 2026-03-22).


def generate_attacker_narratives(data, desc_cache=None):
    """Generate ONE narrative per attacker IP, grouping all sessions and deduplicating commands.
    H1/H3 fix: accepts shared desc_cache from caller; if None, loads own copy."""
    geo_cache = data.get("geo_cache", {})
    ip_creds_map = data.get("ip_creds", {})
    _owns_cache = desc_cache is None
    if _owns_cache:
        desc_cache = load_cache()

    # Group successful sessions by IP
    ip_sessions = defaultdict(list)
    for s in data.get("successful_sessions", []):
        ip_sessions[s["ip"]].append(s)

    if not ip_sessions:
        return []

    results = []
    llm_calls = 0
    MAX_LLM_CALLS = 10

    for ip, sessions in ip_sessions.items():
        geo = geo_cache.get(ip, {})
        nick = generate_nickname(ip, geo, ip_creds_map.get(ip, []))
        country = geo.get("country", "Unknown")
        city = geo.get("city", "")
        isp = geo.get("isp", "Unknown")
        loc = f"{city}, {country}" if city else country

        # Collect ALL commands across all sessions, preserving order of first appearance
        all_cmds_ordered = []
        cmd_counts = Counter()
        seen_cmds = set()
        all_creds = set()
        first_ts = None
        last_ts = None

        for s in sessions:
            if s.get("creds"):
                all_creds.add(s["creds"])
            for c in s["commands"]:
                cmd = c["cmd"]
                cmd_counts[cmd] += 1
                if cmd not in seen_cmds:
                    seen_cmds.add(cmd)
                    all_cmds_ordered.append(cmd)
                # Track time range
                ts = c.get("ts", "")
                if ts:
                    if first_ts is None or ts < first_ts:
                        first_ts = ts
                    if last_ts is None or ts > last_ts:
                        last_ts = ts

        total_cmd_executions = sum(cmd_counts.values())
        unique_cmd_count = len(all_cmds_ordered)
        creds_str = ", ".join(sorted(all_creds)[:3]) or "unknown"

        # Build cache key from IP + sorted unique commands
        cmd_hash = hashlib.md5(str(sorted(seen_cmds)).encode()).hexdigest()[:8]
        cache_key = f"atk_{ip}_{cmd_hash}"

        cached = _cache_get(desc_cache, cache_key)
        if cached:
            is_valid, _reason = validate_llm_output(cached, max_chars=350)
            if is_valid and '**' not in cached:
                narrative = cached
            else:
                print(f"[*] Cached narrative for {cache_key} failed validation, regenerating")
                narrative = None
                if cache_key in desc_cache:
                    del desc_cache[cache_key]
        else:
            narrative = None
        if narrative is None:
            # Build the narrative
            # For simple cases (all same command), use a template
            if unique_cmd_count == 0:
                narrative = f"Logged in across {len(sessions)} sessions but ran no commands."
            elif unique_cmd_count == 1 and any(
                k in all_cmds_ordered[0].lower() for k in ["uname", "/bin/./uname"]
            ):
                narrative = f"Ran uname {total_cmd_executions}x across {len(sessions)} sessions — automated OS fingerprinting."
            elif unique_cmd_count <= 3 and total_cmd_executions == unique_cmd_count:
                # Few unique commands, each run once — use annotations
                steps = []
                for cmd in all_cmds_ordered:
                    ann = annotate_command(cmd)
                    if ann:
                        steps.append(ann)
                    else:
                        # Use the command basename
                        base = cmd.strip().split()[0].split("/")[-1] if cmd.strip() else "?"
                        steps.append(base)
                narrative = " → ".join(steps)
            elif unique_cmd_count <= 6:
                # Moderate complexity — build arrow chain from annotations
                steps = []
                for cmd in all_cmds_ordered:
                    ann = annotate_command(cmd)
                    if ann and ann not in steps:
                        steps.append(ann)
                    elif not ann:
                        base = cmd.strip().split()[0].split("/")[-1] if cmd.strip() else "?"
                        if base not in steps:
                            steps.append(base)
                # Add repetition note if significant
                repeated = [(cmd, cnt) for cmd, cnt in cmd_counts.items() if cnt > 2]
                narrative = " → ".join(steps)
                if repeated:
                    top_repeated = max(repeated, key=lambda x: x[1])
                    # Guard against empty/whitespace command strings: "".split()
                    # is [] and [0] would raise IndexError (production crash:
                    # [FATAL] list index out of range). Fall back to "?".
                    top_cmd = top_repeated[0].strip()
                    ann = annotate_command(top_repeated[0]) or (
                        top_cmd.split()[0].split("/")[-1] if top_cmd else "?"
                    )
                    narrative += f" (repeated {ann} {top_repeated[1]}x)"
            else:
                # Complex command set — use LLM
                if llm_calls < MAX_LLM_CALLS:
                    llm_calls += 1
                    # Build deduplicated command summary for prompt
                    cmd_summary_parts = []
                    for cmd in all_cmds_ordered[:15]:
                        count = cmd_counts[cmd]
                        if count > 1:
                            cmd_summary_parts.append(f"{cmd}  (x{count})")
                        else:
                            cmd_summary_parts.append(cmd)
                    # Sanitize: truncate long commands and strip control characters
                    cmd_summary_parts = [
                        re.sub(r"[\x00-\x1f\x7f-\x9f]", "", part[:100])
                        for part in cmd_summary_parts
                    ]
                    cmd_block = "\n".join(cmd_summary_parts)

                    prompt = (
                        "用箭头链（→）简短总结这个 SSH 蜜罐攻击者的行为。每步用 → 连接，技术精确，不要前言和引号。\n\n"
                        "示例: uname 指纹探测 → 硬件全面审计（lscpu, dmidecode, free）→ 枚举 PCI 设备 → 评估挖矿潜力\n\n"
                        "示例: wget 下载 payload → chmod +x → 执行二进制 → 尝试 crontab 持久化\n\n"
                        f"攻击者: {nick}，来自 {loc}（{isp}）\n"
                        f"会话数: {len(sessions)}，总命令数: {total_cmd_executions}，"
                        f"独立命令数: {unique_cmd_count}\n"
                        f"凭证: {creds_str}\n"
                        f"命令（去重后按顺序）:\n{cmd_block}\n\n"
                        "箭头链总结:"
                    )
                    narrative = llm_generate(prompt, temperature=0.5, max_tokens=80)
                    narrative = strip_markdown(narrative)
                    # Strip leading arrow from prompt format
                    narrative = re.sub(r'^[\u2192\u2192]\s*', '', narrative).strip()

                    # Validate — inline bad-starts consolidated into _BAD_PREFIXES (M1 fix)
                    is_valid, reason = validate_llm_output(narrative)
                    if not is_valid or len(narrative) < 10:
                        narrative = None

                if not narrative:
                    # Fallback: build from annotations
                    steps = []
                    for cmd in all_cmds_ordered[:10]:
                        ann = annotate_command(cmd)
                        if ann and ann not in steps:
                            steps.append(ann)
                    narrative = " → ".join(steps) if steps else f"Ran {unique_cmd_count} unique commands across {len(sessions)} sessions."

            # Clean up
            narrative = narrative.strip('"').strip()
            if len(narrative) > 300:
                narrative = narrative[:297].rsplit(" ", 1)[0] + "..."

            desc_cache[cache_key] = {
                "text": narrative,
                "_cached_at": datetime.now(timezone.utc).isoformat()
            }

        # Build the display commands: deduplicated with counts
        display_cmds = []
        for cmd in all_cmds_ordered:
            count = cmd_counts[cmd]
            display_cmds.append({"cmd": cmd, "count": count})

        results.append({
            "ip": ip,
            "nick": nick,
            "loc": loc,
            "sessions": len(sessions),
            "total_cmds": total_cmd_executions,
            "unique_cmds": unique_cmd_count,
            "creds": creds_str,
            "narrative": narrative,
            "display_cmds": display_cmds,
            "first_ts": first_ts,
            "last_ts": last_ts,
        })

    if _owns_cache:
        save_cache(desc_cache)
    return results





def generate_html(data):
    stats = data["stats"]
    today = data["today_stats"]
    last_24h = data.get("last_24h", {})
    peak_sessions = data.get("peak_sessions", (0, "—"))
    peak_logins = data.get("peak_logins", (0, "—"))
    peak_successful = data.get("peak_successful", (0, "—"))
    peak_commands = data.get("peak_commands", (0, "—"))
    peak_ips = data.get("peak_ips", (0, "—"))
    peak_success_rate = data.get("peak_success_rate", (0, "—"))
    geo_cache = data.get("geo_cache", {})
    ip_creds = data.get("ip_creds", {})
    markers_json = json.dumps(data["markers"])
    daily_breakdown_json = json.dumps(data["daily_breakdown"])
    top_creds_labels = json.dumps([c[0] for c in data["top_creds"][:15]])
    top_creds_data = json.dumps([c[1] for c in data["top_creds"][:15]])
    timeline_labels = json.dumps(data["timeline_labels"])
    timeline_data = json.dumps(data["timeline_data"])

    # H1/H3 fix: load cache once, share between both LLM generation passes, save once at end
    print("[*] Loading description cache...")
    shared_desc_cache = load_cache()

    print("[*] Generating greatest hits (LLM)...")
    greatest_hits = generate_greatest_hits(data, desc_cache=shared_desc_cache)
    greatest_hits_html = ""
    for hit in greatest_hits:
        greatest_hits_html += f"""
        <div class="hit-card">
            <div class="hit-nick" onclick="flyToAttacker('{hit['nick']}')">{hit['flag']} {hit['nick']}</div>
            <div class="hit-stat">{hit['count']}{LOCALE['unit_attempts']}{' \u00b7 ' + str(hit.get('sessions', 0)) + LOCALE['unit_sessions'] if hit.get('sessions') else ''}{' \u00b7 ' + str(hit['cmds']) + LOCALE['unit_cmds'] if hit['cmds'] else ''}</div>
            <div class="hit-story">{h(hit['story'])}</div>
            <div style="color:#555;font-size:0.75em;margin-top:4px;">\u23f0 {hit['time_range']}</div>
        </div>"""
    if not greatest_hits_html:
        greatest_hits_html = f'<div style="color:#666;">{LOCALE["no_attackers"]}</div>'

    print("[*] Generating attacker narratives...")
    attacker_narratives = generate_attacker_narratives(data, desc_cache=shared_desc_cache)

    # Save merged cache once after both passes complete
    save_cache(shared_desc_cache)

    leaderboard_rows = ""
    for i, a in enumerate(data["top_attackers"], 1):
        city_or_country = h(a['city']) if a['city'] else h(a['country'])
        leaderboard_rows += f"""
        <tr>
            <td><span class="nick-link" onclick="flyToAttacker(&quot;{a['nickname']}&quot;)">{a['nickname']}</span><br><span style="color:#666;font-size:0.8em">{a['ip']}</span></td>
            <td>{a['flag']} {city_or_country}</td>
            <td class="hide-mobile">{h(a['isp'])}</td>
            <td class="glow">{a['count']}</td>
        </tr>"""

    activity_rows = ""
    prev_ip = None
    for ev in reversed(data["recent_events"]):
        try:
            dt_ev = datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))
            ts_short = dt_ev.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, AttributeError):
            ts_short = ev["ts"][:19].replace("T", " ") if ev["ts"] else "?"
        # Show time range for grouped events
        count = ev.get("count", 1)
        if count > 1:
            try:
                first_dt = datetime.fromisoformat(ev["first_ts"].replace("Z", "+00:00")).astimezone(LOCAL_TZ)
                last_dt = datetime.fromisoformat(ev["last_ts"].replace("Z", "+00:00")).astimezone(LOCAL_TZ)
                if first_dt.date() == last_dt.date():
                    ts_short = f"{first_dt.strftime('%H:%M')} – {last_dt.strftime('%H:%M')}"
                else:
                    ts_short = f"{first_dt.strftime('%m-%d %H:%M')} – {last_dt.strftime('%m-%d %H:%M')}"
            except (ValueError, AttributeError):
                pass
        count_badge = f'<span class="count-badge">{count}×</span> ' if count > 1 else ""
        action_class = "success-text" if "SUCCESS" in ev["action"] else ""
        geo = geo_cache.get(ev['ip'], {})
        nick = generate_nickname(ev['ip'], geo, ip_creds.get(ev['ip'], []))
        # Suppress repeated IPs
        show_ip = ev["ip"] if ev["ip"] != prev_ip else "↑"
        prev_ip = ev["ip"]
        # Action already html-escaped at creation time — no double-escape
        activity_rows += f"""
        <div class="activity-row">
            <span class="ts">{ts_short}</span>
            <span class="nick-link" onclick="flyToAttacker(&quot;{nick}&quot;)">{nick}</span>
            <span class="ip">{show_ip}</span>
            <span class="action {action_class}">{count_badge}{ev['action']}</span>
        </div>"""

    terminal_content = ""
    if attacker_narratives:
        for atk in attacker_narratives:
            session_word = "session" if atk["sessions"] == 1 else "sessions"
            cmd_word = "cmd" if atk["total_cmds"] == 1 else "cmds"
            terminal_content += f'<div class="term-ip-group">'
            terminal_content += (
                f'<div class="term-ip-header">'
                f'<span class="nick-link" onclick="flyToAttacker(&quot;{atk["nick"]}&quot;)">'
                f'\U0001f3ad {atk["nick"]}</span> ({atk["ip"]}) '
                f'\u2014 {atk["loc"]} \u00b7 {atk["sessions"]} {session_word} '
                f'\u00b7 {atk["total_cmds"]} {cmd_word}</div>'
            )
            terminal_content += '<div class="session-block">'
            # Time range
            time_parts = []
            if atk.get("first_ts"):
                try:
                    utc_dt = datetime.fromisoformat(atk["first_ts"].replace("Z", "+00:00")[:26]).replace(tzinfo=timezone.utc)
                    local_dt = utc_dt.astimezone(ZoneInfo("America/New_York"))
                    time_parts.append(local_dt.strftime("%Y-%m-%d %H:%M %Z"))
                except (ValueError, TypeError):
                    time_parts.append(atk["first_ts"][:16].replace("T", " "))
            if atk.get("creds"):
                time_parts.append(f'as {atk["creds"]}')
            meta = " \u00b7 ".join(time_parts)
            if meta:
                terminal_content += f'<div class="session-meta">{meta}</div>'
            terminal_content += f'<div class="session-narrative">{h(atk["narrative"])}</div>'
            # Show deduplicated commands with counts
            if atk.get("display_cmds"):
                terminal_content += '<div class="session-cmds">'
                for dc in atk["display_cmds"]:
                    count_badge = f' <span class="cmd-count">\u00d7{dc["count"]}</span>' if dc["count"] > 1 else ""
                    annotation = annotate_command(dc["cmd"])
                    note_html = f'<div class="cmd-annotation">↳ {annotation}</div>' if annotation else ""
                    terminal_content += f'<div class="cmd-line"><span class="cmd-prompt">$</span> {h(dc["cmd"])}{count_badge}</div>{note_html}'
                terminal_content += '</div>'
            terminal_content += '</div></div>'
    elif data["successful_sessions"]:
        for s in data["successful_sessions"]:
            geo = geo_cache.get(s["ip"], {})
            nick = generate_nickname(s["ip"], geo, ip_creds.get(s["ip"], []))
            terminal_content += f'<div class="term-header">\U0001f3ad {nick} ({s["ip"]})</div>'
            for cmd in s["commands"]:
                annotation = annotate_command(cmd["cmd"])
                note_html = f'<div class="cmd-annotation">↳ {annotation}</div>' if annotation else ""
                terminal_content += f'<div class="term-line"><span class="term-prompt">$ </span>{h(cmd["cmd"])}</div>{note_html}'
    else:
        terminal_content = f'<div class="term-line" style="color:#666;">{LOCALE["no_successful_logins"]}</div>'

    daily_rows = ""
    for d in data["daily_breakdown"]:
        attacker_cell = f'<span class="nick-link" onclick="flyToAttacker(&quot;{d["top_attacker_nick"]}&quot;)">{d["top_attacker_nick"]}</span> <span style="color:#555">({d["top_attacker_ip"]})</span>' if d["top_attacker_ip"] else '<span style="color:#555">\u2014</span>'
        daily_rows += f"""
        <tr>
            <td class="glow">{d['date']}</td>
            <td>{d['sessions']}</td>
            <td class="hide-mobile">{d['login_attempts']}</td>
            <td>{d['successful']}</td>
            <td>{d['unique_ips']}</td>
            <td class="hide-mobile">{d['commands']}</td>
            <td class="hide-mobile">{attacker_cell}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="{LOCALE['lang']}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>{LOCALE['page_title']}</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🍯</text></svg>">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@400;700;900&display=swap');

  @keyframes pulse-ring {{
    0% {{ transform: scale(1); opacity: 0.8; }}
    50% {{ transform: scale(1.8); opacity: 0; }}
    100% {{ transform: scale(1); opacity: 0; }}
  }}
  @keyframes pulse-dot {{
    0% {{ opacity: 0.6; box-shadow: 0 0 4px #ff0000; }}
    50% {{ opacity: 1.0; box-shadow: 0 0 12px #ff4444, 0 0 24px #ff000066; }}
    100% {{ opacity: 0.6; box-shadow: 0 0 4px #ff0000; }}
  }}
  .pulse-marker {{
    position: relative;
    will-change: transform;
  }}
  .pulse-marker .dot {{
    width: 100%;
    height: 100%;
    background: radial-gradient(circle, #ff4444 0%, #cc0000 70%);
    border-radius: 50%;
    animation: pulse-dot 2s ease-in-out infinite;
  }}
  .pulse-marker .ring {{
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    border: 2px solid #ff4444;
    border-radius: 50%;
    animation: pulse-ring 2s ease-out infinite;
    pointer-events: none;
  }}
  .leaflet-zoom-anim .leaflet-marker-icon {{
    transition: transform 0.25s cubic-bezier(0,0,0.25,1) !important;
  }}
  .leaflet-pan-anim .leaflet-marker-icon {{
    transition: transform 0.25s linear !important;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  html {{
    overflow-x: hidden;
    max-width: 100vw;
  }}
  body {{
    background: #0a0a0a;
    color: #00ff41;
    font-family: 'JetBrains Mono', monospace;
    overflow-x: hidden;
    max-width: 100vw;
    -webkit-text-size-adjust: 100%;
  }}

  .scanline {{
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,65,0.03) 2px, rgba(0,255,65,0.03) 4px);
    pointer-events: none; z-index: 9999;
  }}

  header {{
    background: linear-gradient(180deg, #0d1117 0%, #0a0a0a 100%);
    border-bottom: 1px solid #00ff41;
    padding: 20px 30px;
    text-align: center;
  }}
  header h1 {{
    font-family: 'Orbitron', sans-serif;
    font-size: 2.2em;
    color: #00ff41;
    text-shadow: 0 0 20px rgba(0,255,65,0.5), 0 0 40px rgba(0,255,65,0.2);
    letter-spacing: 3px;
  }}
  header .subtitle {{
    color: #555;
    font-size: 0.85em;
    margin-top: 5px;
  }}

  .stats-bar {{
    display: flex;
    justify-content: center;
    gap: 30px;
    padding: 20px;
    background: #0d1117;
    border-bottom: 1px solid #1a3a1a;
    flex-wrap: wrap;
  }}
  .stat {{
    text-align: center;
    min-width: 120px;
  }}
  .stat .value {{
    font-family: 'Orbitron', sans-serif;
    font-size: 2em;
    color: #00ff41;
    text-shadow: 0 0 10px rgba(0,255,65,0.4);
  }}
  .stat .label {{
    font-size: 0.75em;
    color: #666;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
  }}

  .alltime-bar {{
    background: transparent;
    display: flex;
    justify-content: center;
    gap: 20px;
    padding: 12px 20px;
    background: #080c10;
    border-bottom: 1px solid #1a3a1a;
    flex-wrap: wrap;
  }}
  .alltime-stat {{
    text-align: center;
    min-width: 90px;
  }}
  .alltime-value {{
    font-family: 'Orbitron', sans-serif;
    font-size: 1.2em;
    color: #00aa30;
    text-shadow: 0 0 6px rgba(0,170,48,0.3);
  }}
  .alltime-label {{
    font-size: 0.65em;
    color: #555;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 3px;
  }}

  .container {{
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
    width: 100%;
    overflow-x: hidden;
  }}

  .grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 20px;
    max-width: 100%;
  }}
  .grid.full {{ grid-template-columns: 1fr; max-width: 100%; }}

  .panel {{
    background: #0d1117;
    border: 1px solid #1a3a1a;
    border-radius: 8px;
    padding: 20px;
    position: relative;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    min-height: 0;
    width: 100%;
    max-width: 100%;
  }}
  .panel::before {{
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 2px;
    background: linear-gradient(90deg, transparent, #00ff41, transparent);
  }}
  .panel h2 {{
    font-family: 'Orbitron', sans-serif;
    font-size: 1.1em;
    color: #00ff41;
    margin-bottom: 15px;
    text-transform: uppercase;
    letter-spacing: 2px;
  }}

  #map {{
    height: 400px;
    min-height: 400px;
    border-radius: 6px;
    border: 1px solid #1a3a1a;
    background: #0a0a0a;
    z-index: 1;
    position: relative;
  }}
  .leaflet-container {{
    background: #0a0a0a !important;
  }}
  #map .leaflet-tile-pane {{
    z-index: 1;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
    word-break: break-word;
  }}
  th, td {{
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid #1a2a1a;
    font-size: 0.85em;
  }}
  th {{
    color: #00aa30;
    text-transform: uppercase;
    font-size: 0.75em;
    letter-spacing: 1px;
  }}
  td {{ color: #aaa; }}
  .glow {{ color: #00ff41; font-weight: bold; text-shadow: 0 0 5px rgba(0,255,65,0.3); }}

  .activity-feed {{
    height: 350px;
    max-height: 350px;
    overflow-y: auto;
    font-size: 0.82em;
    flex: 1;
  }}
  .greatest-hits {{
    max-height: 500px;
    overflow-y: auto;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }}
  .hit-card {{
    background: #111a11;
    border: 1px solid #1a3a1a;
    border-radius: 6px;
    padding: 12px;
  }}
  .hit-card .hit-nick {{
    color: #ff4444;
    font-weight: bold;
    font-size: 1.1em;
    cursor: pointer;
  }}
  .hit-card .hit-nick:hover {{
    text-shadow: 0 0 8px rgba(255,68,68,0.5);
  }}
  .hit-card .hit-stat {{
    color: #00ff41;
    font-family: 'Orbitron', sans-serif;
    font-size: 0.85em;
    margin: 4px 0;
  }}
  .hit-card .hit-story {{
    color: #aaa;
    font-size: 0.85em;
    margin-top: 6px;
    line-height: 1.4;
  }}
  .activity-feed::-webkit-scrollbar {{ width: 6px; }}
  .activity-feed::-webkit-scrollbar-track {{ background: #0a0a0a; }}
  .activity-feed::-webkit-scrollbar-thumb {{ background: #1a3a1a; border-radius: 3px; }}

  .activity-row {{
    padding: 6px 10px;
    border-bottom: 1px solid #111;
    display: flex;
    gap: 12px;
    align-items: baseline;
  }}
  .activity-row:hover {{ background: #111a11; }}
  .activity-row .ts {{ color: #444; min-width: 150px; font-size: 0.9em; }}
  .activity-row .ip {{ color: #ff6b6b; min-width: 130px; }}
  .count-badge {{
    background: #ff6b35; color: #000; padding: 1px 6px;
    border-radius: 8px; font-size: 0.8em; font-weight: bold;
  }}
  .activity-row .action {{ color: #aaa; flex: 1; min-width: 0; max-height: 80px; overflow-y: auto; overflow-x: hidden; word-break: break-all; white-space: pre-wrap; }}
  .activity-row .action::-webkit-scrollbar {{ width: 4px; }}
  .activity-row .action::-webkit-scrollbar-track {{ background: #0a0a0a; }}
  .activity-row .action::-webkit-scrollbar-thumb {{ background: #1a3a1a; border-radius: 3px; }}
  .success-text {{ color: #00ff41 !important; font-weight: bold; }}
  .nick-link {{
    color: #ff4444;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .nick-link:hover {{
    color: #ff6666;
    text-decoration: underline;
    text-shadow: 0 0 8px rgba(255,68,68,0.5);
  }}

  .terminal {{
    background: #000;
    border: 1px solid #1a3a1a;
    border-radius: 6px;
    padding: 15px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85em;
    max-height: 350px;
    overflow-y: auto;
    overflow-x: hidden;
    word-break: break-all;
    white-space: pre-wrap;
    max-width: 100%;
  }}
  .term-header {{
    color: #ff6b6b;
    font-weight: bold;
    margin: 10px 0 5px 0;
    border-bottom: 1px solid #222;
    padding-bottom: 3px;
  }}
  .term-line {{ color: #00ff41; margin: 2px 0; word-break: break-all; overflow-wrap: break-word; }}
  .cmd-note {{
    color: #0a8;
    font-style: italic;
    font-size: 0.85em;
    opacity: 0.7;
    margin-left: 8px;
  }}
  .term-prompt {{ color: #ff6b6b; }}

  .leaflet-popup-content-wrapper {{
    background: #0d1117 !important;
    color: #00ff41 !important;
    border: 1px solid #00ff41 !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
  }}
  .leaflet-popup-tip {{ background: #0d1117 !important; }}
  .leaflet-popup-content {{ font-size: 0.85em; }}
  .popup-ip {{ color: #ff6b6b; font-weight: bold; font-size: 1.1em; }}
  .popup-label {{ color: #666; }}

  .footer {{
    text-align: center;
    padding: 20px;
    color: #333;
    font-size: 0.8em;
  }}

  canvas {{ max-height: 300px; }}

  @media (max-width: 900px) {{
    .grid {{ grid-template-columns: 1fr; }}
    .stats-bar {{ gap: 15px; }}
  }}
  @media (max-width: 600px) {{
    header h1 {{ font-size: 1.1em; letter-spacing: 1px; }}
    header .subtitle {{ font-size: 0.65em; word-break: break-word; }}
    .container {{ padding: 8px; }}
    .panel {{ padding: 10px; overflow: hidden; max-width: 100vw; }}
    .panel > div {{ overflow-x: auto; -webkit-overflow-scrolling: touch; }}
    .panel h2 {{ font-size: 0.85em; letter-spacing: 1px; }}

    .stats-bar {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; padding: 10px 8px; }}
    .stat {{ min-width: unset; }}
    .stat .value {{ font-size: 1.3em; }}
    .stat .label {{ font-size: 0.55em; }}
    .alltime-bar {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 6px; padding: 8px; }}
    .alltime-stat {{ min-width: unset; }}
    .alltime-value {{ font-size: 0.95em; }}
    .alltime-label {{ font-size: 0.5em; }}

    .activity-row {{ flex-wrap: wrap; gap: 2px; padding: 8px 6px; }}
    .activity-row .ts {{ min-width: unset; font-size: 0.7em; width: 100%; }}
    .activity-row .ip {{ min-width: unset; font-size: 0.8em; }}
    .activity-row .action {{ font-size: 0.75em; width: 100%; max-height: 60px; }}

    .hide-mobile {{ display: none !important; }}
    table {{ font-size: 0.85em; }}
    table td, table th {{ padding: 8px 6px; }}

    .terminal {{ font-size: 0.7em; padding: 8px; }}
    .greatest-hits {{ grid-template-columns: 1fr; }}
    #map {{ height: 280px; }}
    canvas {{ max-height: 200px; }}

    .leaflet-marker-icon {{ transition: none !important; }}

    html, body {{ touch-action: pan-x pan-y; max-width: 100vw; }}
    .container {{ max-width: 100vw; padding: 6px; overflow-x: hidden; }}
    .grid {{ gap: 10px; margin-bottom: 10px; }}
    .grid.full {{ max-width: 100%; }}
  }}

  .term-ip-group {{
    margin-bottom: 16px;
    border-bottom: 1px solid #1a3a1a;
    padding-bottom: 12px;
  }}
  .term-ip-header {{
    color: #ff6b6b;
    font-weight: bold;
    font-size: 1.05em;
    margin-bottom: 8px;
    padding-bottom: 4px;
    cursor: pointer;
  }}
  .session-block {{
    margin: 4px 0 4px 12px;
    padding: 4px 12px;
    border-left: 2px solid #1a3a1a;
  }}
  .session-meta {{
    color: #555;
    font-size: 0.8em;
    margin-bottom: 4px;
  }}
  .session-narrative {{
    color: #ff8c00;
    font-size: 0.85em;
    font-style: italic;
    line-height: 1.4;
  }}
  .session-cmds {{
    color: #00ff41;
    font-size: 0.82em;
    margin-top: 4px;
    line-height: 1.5;
  }}
  .session-cmds .cmd-line {{
    margin: 2px 0;
    overflow-wrap: break-word;
    word-break: break-all;
    white-space: pre-wrap;
  }}
  .session-cmds .cmd-prompt {{
    color: #888;
  }}
  .cmd-annotation {{
    display: block;
    color: #0a8;
    font-style: italic;
    font-size: 0.82em;
    opacity: 0.8;
    margin-left: 18px;
    margin-bottom: 2px;
  }}
</style>
</head>
<body>

<div class="scanline"></div>

<header>
  <h1>{LOCALE['header_title']}</h1>
  <div class="subtitle">{LOCALE['header_subtitle'].format(generated=data['generated'])}</div>
</header>

<div class="stats-bar">
  <div class="stat"><div class="value">{today['sessions']}</div><div class="label">{LOCALE['sessions_today']}</div></div>
  <div class="stat"><div class="value">{today['login_attempts']}</div><div class="label">{LOCALE['login_attempts_today']}</div></div>
  <div class="stat"><div class="value">{today['successful_logins']}</div><div class="label">{LOCALE['successful_logins_today']}</div></div>
  <div class="stat"><div class="value">{today['unique_ips']}</div><div class="label">{LOCALE['unique_ips_today']}</div></div>
  <div class="stat"><div class="value">{today['commands']}</div><div class="label">{LOCALE['commands_today']}</div></div>
</div>


<div class="container">

  <div class="grid full">
    <div class="panel" style="overflow:visible;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:15px;">
        <h2 style="margin-bottom:0;">{LOCALE['attack_origins']}</h2>
        <div style="display:flex;align-items:center;gap:10px;">
          <button onclick="changeWeek(-1)" id="weekPrev" style="background:none;border:1px solid #333;color:#888;font-size:1.2em;cursor:pointer;padding:4px 10px;border-radius:4px;font-family:monospace;">&larr;</button>
          <span id="weekLabel" style="color:#888;font-size:0.85em;font-family:'JetBrains Mono',monospace;min-width:140px;text-align:center;"></span>
          <button onclick="changeWeek(1)" id="weekNext" style="background:none;border:1px solid #333;color:#888;font-size:1.2em;cursor:pointer;padding:4px 10px;border-radius:4px;font-family:monospace;">&rarr;</button>
        </div>
      </div>
      <div id="map"></div>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>{LOCALE['top_attackers']}</h2>
      <div style="max-height:350px; overflow-y:auto;">
        <table>
          <tr><th>{LOCALE['th_attacker']}</th><th>{LOCALE['th_origin']}</th><th class="hide-mobile">{LOCALE['th_isp']}</th><th>{LOCALE['th_attempts']}</th></tr>
          {leaderboard_rows}
        </table>
      </div>
    </div>
    <div class="panel">
      <h2>{LOCALE['recent_activity']}</h2>
      <div class="activity-feed">
        {activity_rows}
      </div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>{LOCALE['greatest_hits']}</h2>
      <div class="greatest-hits">
        {greatest_hits_html}
      </div>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>{LOCALE['top_credentials']}</h2>
      <canvas id="credsChart"></canvas>
    </div>
    <div class="panel">
      <h2 style="margin-bottom:0;">{LOCALE['attack_timeline']}</h2>
      <div id="timelineWeekLabel" style="color:#888;font-size:0.75em;margin-bottom:10px;font-family:'JetBrains Mono',monospace;"></div>
      <canvas id="timelineChart"></canvas>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>{LOCALE['daily_breakdown']}</h2>
      <div id="dailyBreakdown" style="overflow-x:auto; max-height:400px; overflow-y:auto;">
        <table>
          <tr><th>{LOCALE['th_date']}</th><th>{LOCALE['th_sessions']}</th><th class="hide-mobile">{LOCALE['th_login_attempts']}</th><th>{LOCALE['th_successful']}</th><th>{LOCALE['th_unique_ips']}</th><th class="hide-mobile">{LOCALE['th_commands']}</th><th class="hide-mobile">{LOCALE['th_top_attacker']}</th></tr>
          {daily_rows}
        </table>
      </div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>{LOCALE['all_time_stats']}</h2>
      <div style="overflow-x:auto;">
        <table>
          <tr><th>{LOCALE['th_metric']}</th><th>{LOCALE['th_total']}</th><th>{LOCALE['th_avg_day']}</th><th>{LOCALE['th_last_24h']}</th><th>{LOCALE['th_peak_day']}</th></tr>
          <tr><td>{LOCALE['metric_sessions']}</td><td class="glow">{stats['total_sessions']:,}</td><td>{data['averages']['sessions_per_day']}</td><td>{last_24h.get('sessions', 0):,}</td><td>{peak_sessions[0]:,} ({peak_sessions[1]})</td></tr>
          <tr><td>{LOCALE['metric_login_attempts']}</td><td class="glow">{stats['total_login_attempts']:,}</td><td>{data['averages']['logins_per_day']}</td><td>{last_24h.get('login_attempts', 0):,}</td><td>{peak_logins[0]:,} ({peak_logins[1]})</td></tr>
          <tr><td>{LOCALE['metric_successful_logins']}</td><td class="glow">{stats['successful_logins']:,}</td><td>{data['averages']['successful_per_day']}</td><td>{last_24h.get('successful_logins', 0):,}</td><td>{peak_successful[0]:,} ({peak_successful[1]})</td></tr>
          <tr><td>{LOCALE['metric_unique_ips']}</td><td class="glow">{stats['unique_ips']:,}</td><td>{data['averages']['ips_per_day']}</td><td>{last_24h.get('unique_ips', 0):,}</td><td>{peak_ips[0]:,} ({peak_ips[1]})</td></tr>
          <tr><td>{LOCALE['metric_commands_executed']}</td><td class="glow">{stats['commands_executed']:,}</td><td>{data['averages']['commands_per_day']}</td><td>{last_24h.get('commands', 0):,}</td><td>{peak_commands[0]:,} ({peak_commands[1]})</td></tr>
          <tr><td>{LOCALE['metric_success_rate']}</td><td class="glow">{data['averages']['success_rate']}%</td><td>{round(data['averages']['success_rate'], 1)}%</td><td>{round(last_24h.get('successful_logins', 0) / max(1, last_24h.get('login_attempts', 1)) * 100, 1)}%</td><td>{peak_success_rate[0]}% ({peak_success_rate[1]})</td></tr>
          <tr><td>{LOCALE['metric_days_active']}</td><td class="glow" colspan="4">{data['days_active']}</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>{LOCALE['successful_logins_detail']}</h2>
      <div class="terminal" style="max-height:400px; overflow-y:auto;">
        {terminal_content}
      </div>
    </div>
  </div>

</div>

<div class="footer">
  {LOCALE['footer'].format(generated=data['generated'])}
</div>

<script>
  // Map
  var map = L.map('map', {{
    center: [20, 0],
    zoom: 2,
    zoomControl: true,
    attributionControl: false,
    maxBounds: [[-85, -180], [85, 180]],
    maxBoundsViscosity: 1.0,
    minZoom: 2
  }});

  L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
    maxZoom: 18
  }}).addTo(map);

  setTimeout(function() {{ map.invalidateSize(true); }}, 100);
  setTimeout(function() {{ map.invalidateSize(true); }}, 300);
  setTimeout(function() {{ map.invalidateSize(true); }}, 1000);
  setTimeout(function() {{ map.invalidateSize(true); }}, 2000);
  window.addEventListener('resize', function() {{ map.invalidateSize(true); }});
  document.addEventListener('visibilitychange', function() {{ if (!document.hidden) map.invalidateSize(true); }});

  var markerLookup = {{}};
  var pulseMarkers = [];
  var allMarkers = {markers_json};
  var allTimelineLabels = {timeline_labels};
  var allTimelineData = {timeline_data};
  var allDailyBreakdown = {daily_breakdown_json};

  // Weekly pagination state. Persisted across the page's auto-refresh so you
  // aren't yanked back to the current week while browsing older data.
  var weekOffset = parseInt(localStorage.getItem('hpd_weekOffset'), 10);
  if (isNaN(weekOffset) || weekOffset > 0) weekOffset = 0;

  function getWeekRange(offset) {{
    var now = new Date();
    // Find Monday of current week
    var day = now.getDay();
    var diffToMonday = (day === 0 ? 6 : day - 1);
    var monday = new Date(now);
    monday.setDate(now.getDate() - diffToMonday + (offset * 7));
    monday.setHours(0,0,0,0);
    var sunday = new Date(monday);
    sunday.setDate(monday.getDate() + 6);
    sunday.setHours(23,59,59,999);
    return {{ start: monday, end: sunday }};
  }}

  function fmtDate(d) {{
    var months = {json.dumps(LOCALE['months'], ensure_ascii=False)};
    return months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear();
  }}

  function dateStr(d) {{
    return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0');
  }}

  function getMinWeekOffset() {{
    // Find the earliest date in our data
    var minDate = null;
    allMarkers.forEach(function(m) {{
      if (m.first_seen) {{
        var d = new Date(m.first_seen);
        if (!minDate || d < minDate) minDate = d;
      }}
    }});
    allDailyBreakdown.forEach(function(d) {{
      var dt = new Date(d.date + 'T00:00:00');
      if (!minDate || dt < minDate) minDate = dt;
    }});
    if (!minDate) return 0;
    var now = new Date();
    var diffDays = Math.floor((now - minDate) / (1000*60*60*24));
    return -Math.ceil(diffDays / 7);
  }}

  var mapMarkerLayers = [];

  function updateWeekDisplay() {{
    var range = getWeekRange(weekOffset);
    var label = fmtDate(range.start) + ' \u2013 ' + fmtDate(range.end);
    document.getElementById('weekLabel').textContent = label;
    document.getElementById('timelineWeekLabel').textContent = label;

    // Disable next button if at current week
    document.getElementById('weekNext').disabled = (weekOffset >= 0);
    document.getElementById('weekNext').style.opacity = (weekOffset >= 0) ? '0.3' : '1';
    var minOff = getMinWeekOffset();
    document.getElementById('weekPrev').disabled = (weekOffset <= minOff);
    document.getElementById('weekPrev').style.opacity = (weekOffset <= minOff) ? '0.3' : '1';

    updateMapMarkers(range);
    updateTimeline(range);
    updateDailyBreakdown(range);
  }}

  function updateMapMarkers(range) {{
    // Remove old markers
    mapMarkerLayers.forEach(function(l) {{ map.removeLayer(l); }});
    mapMarkerLayers = [];
    pulseMarkers = [];
    markerLookup = {{}};

    var startStr = dateStr(range.start);
    var endStr = dateStr(range.end);

    allMarkers.forEach(function(m) {{
      // Sum counts for this week only
      var weekCount = 0;
      if (m.daily_counts) {{
        Object.keys(m.daily_counts).forEach(function(day) {{
          if (day >= startStr && day <= endStr) {{
            weekCount += m.daily_counts[day];
          }}
        }});
      }}
      if (weekCount === 0) return; // Skip markers with no activity this week

      var baseRadius = Math.max(6, Math.min(22, weekCount * 2));
      var phase = Math.random() * Math.PI * 2;

      var ring = L.circleMarker([m.lat, m.lon], {{
        radius: baseRadius * 1.8,
        fillColor: '#ff4444',
        fillOpacity: 0,
        color: '#ff4444',
        weight: 2,
        opacity: 0.4
      }}).addTo(map);

      var dot = L.circleMarker([m.lat, m.lon], {{
        radius: baseRadius,
        fillColor: '#ff4444',
        fillOpacity: 0.7,
        color: '#ff6666',
        weight: 2,
        opacity: 0.9
      }}).addTo(map);

      mapMarkerLayers.push(ring);
      mapMarkerLayers.push(dot);
      pulseMarkers.push({{ ring: ring, dot: dot, baseRadius: baseRadius, phase: phase }});

      var credsHtml = m.creds.length > 0
        ? '<br><span class="popup-label">{LOCALE["popup_creds_tried"]}</span><br>' + m.creds.map(function(c) {{ return '&nbsp;&nbsp;' + c; }}).join('<br>')
        : '';

      dot.bindPopup(
        '<span style="color:#ff4444;font-weight:bold;font-size:14px">' + (m.nickname || '?') + '</span><br>' +
        '<span class="popup-ip">' + m.ip + '</span><br>' +
        '<span class="popup-label">{LOCALE["popup_location"]}</span> ' + (m.city ? m.city + ', ' : '') + m.country + '<br>' +
        '<span class="popup-label">{LOCALE["popup_isp"]}</span> ' + m.isp + '<br>' +
        '<span class="popup-label">{LOCALE["popup_attempts"]}</span> <strong>' + weekCount + '</strong>' +
        credsHtml
      );

      if (m.nickname) markerLookup[m.nickname] = dot;
      markerLookup[m.ip] = dot;
    }});
  }}

  var timelineChart = null;

  function updateTimeline(range) {{
    var startStr = dateStr(range.start);
    var endStr = dateStr(range.end);
    var filteredLabels = [];
    var filteredData = [];
    for (var i = 0; i < allTimelineLabels.length; i++) {{
      // Timeline labels are like "2026-02-07 14:00 EST"
      var dayPart = allTimelineLabels[i].substring(0, 10);
      if (dayPart >= startStr && dayPart <= endStr) {{
        filteredLabels.push(allTimelineLabels[i]);
        filteredData.push(allTimelineData[i]);
      }}
    }}

    if (timelineChart) {{
      timelineChart.data.labels = filteredLabels;
      timelineChart.data.datasets[0].data = filteredData;
      timelineChart.update();
    }}
  }}

  function updateDailyBreakdown(range) {{
    var startStr = dateStr(range.start);
    var endStr = dateStr(range.end);
    var container = document.getElementById('dailyBreakdown');
    var html = '<table><tr><th>{LOCALE["th_date"]}</th><th>{LOCALE["th_sessions"]}</th><th class="hide-mobile">{LOCALE["th_login_attempts"]}</th><th>{LOCALE["th_successful"]}</th><th>{LOCALE["th_unique_ips"]}</th><th class="hide-mobile">{LOCALE["th_commands"]}</th><th class="hide-mobile">{LOCALE["th_top_attacker"]}</th></tr>';
    allDailyBreakdown.forEach(function(d) {{
      if (d.date >= startStr && d.date <= endStr) {{
        var attackerCell = d.top_attacker_ip
          ? '<span class="nick-link" onclick="flyToAttacker(&quot;' + d.top_attacker_nick + '&quot;)">' + d.top_attacker_nick + '</span> <span style="color:#555">(' + d.top_attacker_ip + ')</span>'
          : '<span style="color:#555">\u2014</span>';
        html += '<tr><td class="glow">' + d.date + '</td><td>' + d.sessions + '</td><td class="hide-mobile">' + d.login_attempts + '</td><td>' + d.successful + '</td><td>' + d.unique_ips + '</td><td class="hide-mobile">' + d.commands + '</td><td class="hide-mobile">' + attackerCell + '</td></tr>';
      }}
    }});
    html += '</table>';
    container.innerHTML = html;
  }}

  window.changeWeek = function(dir) {{
    var minOff = getMinWeekOffset();
    var newOffset = weekOffset + dir;
    if (newOffset > 0) newOffset = 0;
    if (newOffset < minOff) newOffset = minOff;
    if (newOffset !== weekOffset) {{
      weekOffset = newOffset;
      localStorage.setItem('hpd_weekOffset', weekOffset);
      updateWeekDisplay();
    }}
  }};

  // A restored offset may now be out of range (the data window can shrink) —
  // clamp it to what's available before the first render.
  (function() {{
    var minOff = getMinWeekOffset();
    if (weekOffset < minOff) weekOffset = minOff;
    if (weekOffset > 0) weekOffset = 0;
  }})();
  // Render markers for current week (updateWeekDisplay handles filtering)
  updateWeekDisplay();

  function animatePulse() {{
    var t = Date.now() / 1000;
    pulseMarkers.forEach(function(pm) {{
      var cycle = (Math.sin(t * 2 + pm.phase) + 1) / 2;
      pm.ring.setRadius(pm.baseRadius * (1.4 + cycle * 0.8));
      pm.ring.setStyle({{ opacity: 0.6 - cycle * 0.5, weight: 2 - cycle }});
      pm.dot.setStyle({{ fillOpacity: 0.5 + cycle * 0.3 }});
    }});
    requestAnimationFrame(animatePulse);
  }}
  animatePulse();

  window.flyToAttacker = function(nickname) {{
    var mapEl = document.getElementById('map');
    if (mapEl) {{ mapEl.scrollIntoView({{ behavior: 'smooth', block: 'center' }}); }}
    var m = markerLookup[nickname];
    if (m) {{
      setTimeout(function() {{
        map.flyTo(m.getLatLng(), 6, {{duration: 0.8}});
        setTimeout(function() {{ m.openPopup(); }}, 900);
      }}, 400);
    }}
  }};

  // Credentials chart
  new Chart(document.getElementById('credsChart'), {{
    type: 'bar',
    data: {{
      labels: {top_creds_labels},
      datasets: [{{
        label: '{LOCALE["chart_label_attempts"]}',
        data: {top_creds_data},
        backgroundColor: 'rgba(0, 255, 65, 0.6)',
        borderColor: '#00ff41',
        borderWidth: 1,
      }}]
    }},
    options: {{
      indexAxis: 'y',
      responsive: true,
      plugins: {{
        legend: {{ display: false }},
      }},
      scales: {{
        x: {{
          ticks: {{ color: '#666' }},
          grid: {{ color: '#1a2a1a' }},
        }},
        y: {{
          ticks: {{ color: '#00ff41', font: {{ family: 'JetBrains Mono', size: 11 }} }},
          grid: {{ display: false }},
        }}
      }}
    }}
  }});

  // Timeline chart
  timelineChart = new Chart(document.getElementById('timelineChart'), {{
    type: 'line',
    data: {{
      labels: {timeline_labels},
      datasets: [{{
        label: '{LOCALE["chart_label_attempts"]}',
        data: {timeline_data},
        borderColor: '#00ff41',
        backgroundColor: 'rgba(0, 255, 65, 0.1)',
        fill: true,
        tension: 0.3,
        pointBackgroundColor: '#00ff41',
        pointRadius: 4,
      }}]
    }},
    options: {{
      responsive: true,
      plugins: {{
        legend: {{ display: false }},
      }},
      scales: {{
        x: {{
          ticks: {{ color: '#666', maxRotation: 45, maxTicksLimit: 6, callback: function(val, idx, ticks) {{ var label = this.getLabelForValue(val); var parts = label.split(' '); return parts[0].slice(5) + ' ' + parts[1]; }} }},
          grid: {{ color: '#1a2a1a' }},
        }},
        y: {{
          beginAtZero: true,
          ticks: {{ color: '#666' }},
          grid: {{ color: '#1a2a1a' }},
        }}
      }}
    }}
  }});

</script>

</body>
</html>"""
    return html


def main():
    print("[*] Parsing Cowrie log...")
    rotated = sorted(f for f in glob.glob(LOG_PATH + "*") if f != LOG_PATH)
    log_files = rotated + [LOG_PATH]

    # Stream-filter while loading: apply the 60-day window and dedup per event so
    # the full multi-month log history is never held in memory at once. Previously
    # every rotated file was parsed in full into one list *before* filtering, which
    # was the source of the multi-GB memory peak. The resulting event set (and its
    # order) is identical to the old load -> filter -> dedup sequence.
    cutoff = datetime.now(timezone.utc) - timedelta(days=60)
    seen_files = set()
    seen_events = set()
    events = []
    total_parsed = 0
    dropped_old = 0
    dropped_dup = 0
    for lf in log_files:
        if lf in seen_files:
            continue
        seen_files.add(lf)
        for e in parse_log(lf):
            total_parsed += 1
            # 60-day window. Missing/malformed timestamps are treated as "old"
            # and dropped — same outcome as the previous default-to-year-2000
            # behavior, but without crashing on an unparseable timestamp.
            ts_str = e.get('timestamp', '')
            try:
                ts_dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                dropped_old += 1
                continue
            if ts_dt <= cutoff:
                dropped_old += 1
                continue
            # Dedup on (session, timestamp, eventid), first occurrence wins.
            key = (e.get('session', ''), ts_str, e.get('eventid', ''))
            if key in seen_events:
                dropped_dup += 1
                continue
            seen_events.add(key)
            events.append(e)

    print(f"[*] Loaded {total_parsed} events from {len(seen_files)} files")
    if dropped_old:
        print(f"[*] Filtered to last 60 days: {len(events) + dropped_dup} events (dropped {dropped_old} old)")
    if dropped_dup:
        print(f"[*] After dedup: {len(events)} unique events (removed {dropped_dup} duplicates)")

    if not events:
        print("[!] No events found. Generating empty dashboard.")

    all_ips = set()
    for e in events:
        ip = e.get("src_ip")
        if ip:
            all_ips.add(ip)
    print(f"[*] Found {len(all_ips)} unique IPs")

    geo_cache = load_geo_cache()
    geo_cache = batch_geoip_lookup(all_ips, geo_cache)

    data = analyze_events(events, geo_cache)

    html = generate_html(data)
    tmp_path = OUTPUT_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(html)
    os.rename(tmp_path, OUTPUT_PATH)
    print(f"[\u2713] Dashboard written to {OUTPUT_PATH}")
    print(f"    Sessions: {data['stats']['total_sessions']} | Logins: {data['stats']['total_login_attempts']} | "
          f"Success: {data['stats']['successful_logins']} | IPs: {data['stats']['unique_ips']}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"[FATAL] {e}")
        traceback.print_exc()
        sys.exit(1)
