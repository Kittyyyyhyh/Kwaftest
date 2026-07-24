"""
传输层 — 四种攻击传输模式

1. transport_api:       POST /api/attack.php (方便，自动CSV日志，适合未编码payload)
2. transport_direct:    GET 直连 WAF :8090 (绕过API的urlencode层，适合编码测试)
3. transport_upload_direct: docker exec 直连app容器 (WAF OFF基准)
4. transport_upload_waf:    multipart POST 经WAF :8090 (WAF ON测试)
"""
import sys
import io
import re
import subprocess
import requests
import json
from datetime import datetime
from typing import Optional

# Fix Windows stdout encoding
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    except (AttributeError, OSError):
        pass

BASE_URL = "http://localhost:8090"
DEFAULT_TIMEOUT = 15


def transport_api(sample_dict: dict, run_id: str = "") -> dict:
    """API模式: POST /api/attack.php → 获取结构化JSON响应"""
    try:
        resp = requests.post(f"{BASE_URL}/api/attack.php", json={
            "scenario": sample_dict["scenario"],
            "level": sample_dict["level"],
            "payload": sample_dict["applied_payload"],
            "encoding": "+".join(sample_dict.get("encoding_ids", [])) or "none",
            "waf": sample_dict.get("waf", "on"),
        }, timeout=DEFAULT_TIMEOUT)
        data = resp.json()

        if "error" in data:
            return _error_result(sample_dict, run_id, f"API error: {data['error']}")

        flag = data.get("flag")
        blocked = data.get("waf_blocked", False)
        verify_type = sample_dict.get("verify_type", "honeytoken")
        verify_pattern = sample_dict.get("verify_pattern", "")

        return {
            "run_id": run_id,
            "sample_id": sample_dict["sample_id"],
            "seed_id": sample_dict.get("seed_id", ""),
            "scenario": sample_dict["scenario"],
            "level": sample_dict["level"],
            "category": sample_dict.get("category", ""),
            "encoding_ids": sample_dict.get("encoding_ids", []),
            "applied_payload": sample_dict["applied_payload"],
            "transport": "api",
            "waf_enabled": data.get("waf_enabled", True),
            "timestamp": data.get("timestamp", datetime.now().isoformat()),
            "waf_blocked": blocked,
            "waf_rule_id": data.get("waf_rule_id"),
            "waf_rule_msg": data.get("waf_rule_msg"),
            "http_status": data.get("http_status", 0),
            "flag_captured": flag,
            "verify_type": verify_type,
            "verify_pattern": verify_pattern,
            "flag_verified": bool(flag),
            "attack_successful": bool(flag and not blocked),
            "response_preview": (data.get("response_preview") or "")[:500],
            "error_message": None,
            "retry_count": sample_dict.get("retries", 0),
        }
    except requests.exceptions.ConnectionError:
        return _error_result(sample_dict, run_id, "Connection refused — 靶场未启动?")
    except requests.exceptions.Timeout:
        return _error_result(sample_dict, run_id, "Request timeout")
    except Exception as e:
        return _error_result(sample_dict, run_id, str(e))


def transport_direct(sample_dict: dict, run_id: str = "") -> dict:
    """Direct模式: 直连 WAF :8090，载荷原样放入URL参数，无二次编码"""
    try:
        target = sample_dict.get("http_target", "")
        url_params = sample_dict.get("url_params", {})
        if not target:
            # 自动构建target
            scenario = sample_dict["scenario"]
            level = sample_dict["level"]
            target = f"/{scenario}/level{level}.php"

        # 替换 ${payload} 占位符
        params = {}
        for k, v in url_params.items():
            params[k] = v.replace("${payload}", sample_dict["applied_payload"])

        url = f"{BASE_URL}{target}"
        resp = requests.get(url, params=params, timeout=DEFAULT_TIMEOUT, allow_redirects=False)

        body = resp.text or ""
        blocked = (resp.status_code == 403)
        flag = None
        verify_type = sample_dict.get("verify_type", "honeytoken")
        verify_pattern = sample_dict.get("verify_pattern", "")

        if verify_type == "honeytoken":
            m = re.search(r'hp-[0-9a-f]{8}', body)
            if m: flag = m.group(0)
        elif verify_type == "output":
            pre_match = re.search(r'<pre>(.*?)</pre>', body, re.DOTALL)
            search_area = pre_match.group(1) if pre_match else body
            if verify_pattern and re.search(verify_pattern, search_area):
                flag = verify_pattern

        return {
            "run_id": run_id,
            "sample_id": sample_dict["sample_id"],
            "seed_id": sample_dict.get("seed_id", ""),
            "scenario": sample_dict["scenario"],
            "level": sample_dict["level"],
            "category": sample_dict.get("category", ""),
            "encoding_ids": sample_dict.get("encoding_ids", []),
            "applied_payload": sample_dict["applied_payload"],
            "transport": "direct",
            "waf_enabled": sample_dict.get("waf", "on") == "on",
            "timestamp": datetime.now().isoformat(),
            "waf_blocked": blocked,
            "waf_rule_id": resp.headers.get("X-WAF-Blocked"),
            "waf_score_total": resp.headers.get("X-WAF-Score-Total"),
            "waf_score_sqli": resp.headers.get("X-WAF-Score-SQLi"),
            "waf_score_rce": resp.headers.get("X-WAF-Score-RCE"),
            "http_status": resp.status_code,
            "flag_captured": flag,
            "verify_type": verify_type,
            "verify_pattern": verify_pattern,
            "flag_verified": bool(flag),
            "attack_successful": bool(flag and not blocked),
            "response_preview": body[:500],
            "error_message": None,
            "retry_count": sample_dict.get("retries", 0),
        }
    except requests.exceptions.ConnectionError:
        return _error_result(sample_dict, run_id, "Connection refused")
    except Exception as e:
        return _error_result(sample_dict, run_id, str(e))


def transport_upload_direct(sample_dict: dict, run_id: str = "") -> dict:
    """Upload Direct模式: docker exec 直连app容器（绕过WAF）"""
    try:
        filename = sample_dict.get("filename", "shell.php")
        content = sample_dict["applied_payload"]
        level = sample_dict["level"]
        extra = sample_dict.get("extra_fields", {})

        # 构建 shell 脚本：写文件 → 上传 → 执行webshell
        extra_f = ""
        for k, v in extra.items():
            extra_f += f" -F '{k}={v}'"

        shell = (
            f"cat > /tmp/_ut.php && "
            f"curl -s -F 'file=@/tmp/_ut.php;filename={filename}'{extra_f} "
            f"http://app:80/upload/level{level}.php && "
            f"echo '---EXEC---' && "
            f"curl -s http://app:80/uploads/{filename} && "
            f"rm -f /tmp/_ut.php"
        )

        r = subprocess.run(
            ['docker', 'exec', '-i', 'waf-app', 'sh', '-c', shell],
            input=content,
            capture_output=True, encoding='utf-8', errors='replace', timeout=30
        )
        out = r.stdout or ""
        parts = out.split('---EXEC---')
        upload_body = parts[0] if parts else out
        exec_body = parts[1] if len(parts) > 1 else ""

        upload_ok = '上传成功' in upload_body or '文件已暂存' in upload_body
        flag = None
        for b in [exec_body, upload_body]:
            m = re.search(r'flag\{([^}]+)\}', b)
            if m:
                flag = m.group(0)
                break

        return {
            "run_id": run_id,
            "sample_id": sample_dict["sample_id"],
            "seed_id": sample_dict.get("seed_id", ""),
            "scenario": "upload",
            "level": level,
            "category": sample_dict.get("category", ""),
            "encoding_ids": sample_dict.get("encoding_ids", []),
            "applied_payload": f"file={filename}",
            "transport": "upload_direct",
            "waf_enabled": False,
            "timestamp": datetime.now().isoformat(),
            "waf_blocked": False,
            "http_status": 200 if upload_ok else 500,
            "flag_captured": flag,
            "flag_verified": bool(flag and re.match(sample_dict.get("expected_flag_pattern", ".*"), flag or "")),
            "attack_successful": bool(flag),
            "response_preview": (f"UPLOAD_OK, shell_exec: {exec_body[:200]}" if flag else upload_body[:500]),
            "error_message": None if upload_ok else "Upload failed",
            "retry_count": sample_dict.get("retries", 0),
        }
    except subprocess.TimeoutExpired:
        return _error_result(sample_dict, run_id, "Docker exec timeout")
    except Exception as e:
        return _error_result(sample_dict, run_id, str(e))


def transport_upload_waf(sample_dict: dict, run_id: str = "") -> dict:
    """Upload WAF模式: multipart POST 经 WAF :8090"""
    try:
        filename = sample_dict.get("filename", "shell.php")
        content = sample_dict["applied_payload"]
        content_type = sample_dict.get("content_type", "application/octet-stream")
        level = sample_dict["level"]
        extra = sample_dict.get("extra_fields", {})

        files = {'file': (filename, content, content_type)}
        data = extra or {}

        resp = requests.post(
            f"http://localhost:8090/upload/level{level}.php",
            files=files, data=data, timeout=DEFAULT_TIMEOUT
        )
        body = resp.text
        blocked = (resp.status_code == 403)

        flag = None
        m = re.search(r'flag\{([^}]+)\}', body)
        if m:
            flag = m.group(0)

        # 尝试通过docker exec访问上传的shell
        shell_flag = None
        if not blocked:
            try:
                exec_r = subprocess.run(
                    ['docker', 'exec', 'waf-app', 'curl', '-s',
                     f'http://app:80/uploads/{filename}'],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=5
                )
                fm = re.search(r'flag\{([^}]+)\}', exec_r.stdout or "")
                if fm:
                    shell_flag = fm.group(0)
            except Exception:
                pass

        final_flag = flag or shell_flag

        return {
            "run_id": run_id,
            "sample_id": sample_dict["sample_id"],
            "seed_id": sample_dict.get("seed_id", ""),
            "scenario": "upload",
            "level": level,
            "category": sample_dict.get("category", ""),
            "encoding_ids": sample_dict.get("encoding_ids", []),
            "applied_payload": f"file={filename}",
            "transport": "upload_waf",
            "waf_enabled": True,
            "timestamp": datetime.now().isoformat(),
            "waf_blocked": blocked,
            "http_status": resp.status_code,
            "flag_captured": final_flag,
            "flag_verified": bool(final_flag and re.match(sample_dict.get("expected_flag_pattern", ".*"), final_flag or "")),
            "attack_successful": bool(final_flag and not blocked),
            "response_preview": body[:500],
            "error_message": None,
            "retry_count": sample_dict.get("retries", 0),
        }
    except Exception as e:
        return _error_result(sample_dict, run_id, str(e))


# ============================================================
# 传输分发器
# ============================================================
TRANSPORT_DISPATCH = {
    "api": transport_api,
    "direct": transport_direct,
    "upload_direct": transport_upload_direct,
    "upload_waf": transport_upload_waf,
}


def execute_sample(sample_dict: dict, run_id: str = "") -> dict:
    """分发到对应传输函数执行"""
    transport = sample_dict.get("transport", "api")
    fn = TRANSPORT_DISPATCH.get(transport, transport_api)
    return fn(sample_dict, run_id)


def _error_result(sample_dict: dict, run_id: str, error_msg: str) -> dict:
    return {
        "run_id": run_id,
        "sample_id": sample_dict.get("sample_id", ""),
        "seed_id": sample_dict.get("seed_id", ""),
        "scenario": sample_dict.get("scenario", ""),
        "level": sample_dict.get("level", 0),
        "category": sample_dict.get("category", ""),
        "encoding_ids": sample_dict.get("encoding_ids", []),
        "applied_payload": sample_dict.get("applied_payload", ""),
        "transport": sample_dict.get("transport", "api"),
        "waf_enabled": sample_dict.get("waf", "on") == "on",
        "timestamp": datetime.now().isoformat(),
        "waf_blocked": False,
        "http_status": 0,
        "flag_captured": None,
        "flag_verified": False,
        "attack_successful": False,
        "response_preview": "",
        "error_message": error_msg,
        "retry_count": sample_dict.get("retries", 0),
    }
