import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from openai import OpenAI

import config


_FIXED_MODEL = "deepseek-flash"
_FIXED_REASONING_EFFORT = "high"
_FIXED_THINKING = {"type": "enabled"}
_FIXED_MAX_TOKENS = 65536
_FIXED_TIMEOUT_SECONDS = 300
_FIXED_MAX_RETRIES = 0
_SECRET_TEXT = re.compile(r"(?i)(sk-[A-Za-z0-9_-]{20,})")


def _scrub(value):
    if isinstance(value, dict):
        return {
            key: _scrub(item)
            for key, item in value.items()
            if key.lower() not in {"authorization", "api_key", "apikey", "x-api-key"}
        }
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, str):
        return _SECRET_TEXT.sub("[REDACTED_SECRET]", value)
    return value


def _log_context():
    case_ids = os.getenv("EXPERIMENT_CASE_IDS")
    return {
        "tool": "actaint",
        "dataset": os.getenv("EXPERIMENT_DATASET"),
        "case_id": os.getenv("EXPERIMENT_CASE_ID") or None,
        "case_ids": json.loads(case_ids) if case_ids else None,
        "project_id": os.getenv("EXPERIMENT_PROJECT_ID"),
        "source_file": os.getenv("EXPERIMENT_SOURCE_FILE"),
        "prompt_layout": os.getenv("ACTAINT_PROMPT_LAYOUT", "baseline"),
    }


def _append_jsonl(record):
    path = os.getenv("TOOL_REQUEST_LOG_FILE")
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(_scrub(record), ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(fd, payload[offset:])
    finally:
        os.close(fd)


def _actual_request_body(request_kwargs):
    body = {key: value for key, value in request_kwargs.items() if key != "extra_body"}
    body.update(request_kwargs.get("extra_body", {}))
    return body


def _safe_error_body(exc, raw_payload=None):
    response_obj = getattr(exc, "response", None)
    if response_obj is not None:
        try:
            return _scrub(response_obj.json())
        except Exception:
            try:
                return _scrub(response_obj.text)
            except Exception:
                pass
    body = getattr(exc, "body", None)
    if body is not None:
        return _scrub(body)
    return _scrub(raw_payload)


def call_chatgpt(messages) -> str:
    """Call the fixed DeepSeek protocol and audit each physical request once."""
    api_key = config.gpt_key
    if not api_key:
        raise ValueError("DeepSeek API key is not configured; set DEEPSEEK_API_KEY.")

    call_id = str(uuid.uuid4())
    request_kwargs = {
        "model": _FIXED_MODEL,
        "messages": messages,
        "max_tokens": _FIXED_MAX_TOKENS,
        "n": 1,
        "stop": None,
        "extra_body": {
            "reasoning_effort": _FIXED_REASONING_EFFORT,
            "thinking": _FIXED_THINKING,
        },
    }
    base_event = {
        **_log_context(),
        "call_id": call_id,
        "model": _FIXED_MODEL,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    _append_jsonl({
        **base_event,
        "event": "request",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "request_body": _actual_request_body(request_kwargs),
    })

    http_client = None
    client = None
    raw_payload = None
    started = time.monotonic()
    try:
        http_client = httpx.Client(
            trust_env=False,
            timeout=httpx.Timeout(_FIXED_TIMEOUT_SECONDS),
        )
        client = OpenAI(
            base_url=config.gpt_url or "https://api.deepseek.com",
            api_key=api_key,
            timeout=_FIXED_TIMEOUT_SECONDS,
            max_retries=_FIXED_MAX_RETRIES,
            http_client=http_client,
        )
        raw_response = client.chat.completions.with_raw_response.create(**request_kwargs)
        raw_payload = raw_response.http_response.json()
        response = raw_response.parse()
        elapsed = time.monotonic() - started
        usage = raw_payload.get("usage") or {}
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        total_tokens = usage.get("total_tokens")
        if total_tokens is not None:
            config.total_token += int(total_tokens)

        choices = raw_payload.get("choices") or []
        visible_output = response.choices[0].message.content if response.choices else None
        finish_reason = choices[0].get("finish_reason") if choices else None
        response_id = raw_payload.get("id") or getattr(response, "id", None)
        _append_jsonl({
            **base_event,
            "event": "response",
            "ended_utc": datetime.now(timezone.utc).isoformat(),
            "request_id": response_id,
            "latency_seconds": elapsed,
            "status_code": raw_response.http_response.status_code,
            "finish_reason": finish_reason,
            "response_complete": finish_reason == "stop",
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "prompt_cache_hit_tokens": usage.get("prompt_cache_hit_tokens"),
            "prompt_cache_miss_tokens": usage.get("prompt_cache_miss_tokens"),
            "visible_output": visible_output,
            "raw_response": raw_payload,
        })
        if finish_reason != "stop":
            raise RuntimeError("DeepSeek response ended with finish_reason=length; output is incomplete.")
        if visible_output is None:
            raise RuntimeError("DeepSeek response has no visible message content.")
        return visible_output
    except Exception as exc:
        response_obj = getattr(exc, "response", None)
        _append_jsonl({
            **base_event,
            "event": "error",
            "ended_utc": datetime.now(timezone.utc).isoformat(),
            "latency_seconds": time.monotonic() - started,
            "error_type": type(exc).__name__,
            "status_code": getattr(exc, "status_code", None) or getattr(response_obj, "status_code", None),
            "request_id": getattr(exc, "request_id", None),
            "error_body": _safe_error_body(exc, raw_payload),
        })
        raise
    finally:
        if client is not None:
            client.close()
        elif http_client is not None:
            http_client.close()
