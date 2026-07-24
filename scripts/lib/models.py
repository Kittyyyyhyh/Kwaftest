"""
数据模型定义：Seed, EncodingRecipe, Sample, Result
所有数据类支持 JSON 序列化/反序列化
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict
import json
from datetime import datetime


@dataclass
class Seed:
    """攻击种子 — 一个具体的攻击payload模板"""
    id: str                          # 全局唯一ID，如 "sqli-l1-seed-01"
    scenario: str                    # "sqli" | "cmdi" | "upload"
    level: int                       # 1-5
    category: str                    # "baseline" | "semantic_bypass" | "encoding_bypass" | "combo"
    name: str                        # 人类可读名称
    payload: str                     # 原始攻击载荷（未编码）
    description: str                 # 攻击原理说明
    expected_flag_pattern: str       # 期望的flag正则，如 "flag\\{sqli_l1_.*\\}"
    applicable_transports: List[str] # 可用传输模式
    http_method: str = "GET"         # HTTP 方法
    url_params: Dict[str, str] = field(default_factory=dict)  # URL参数模板，${payload}占位

    # Upload专用字段
    filename: Optional[str] = None
    content_type: Optional[str] = None
    extra_fields: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}

    @classmethod
    def from_dict(cls, d: dict) -> "Seed":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class EncodingRecipe:
    """编码配方 — 一种编码变换的定义"""
    id: str                          # "url" | "double_url" | "base64_cmd" ...
    name: str                        # 人类可读名称
    encode_function: str             # encoders.py 中的函数名
    nestable: bool = False           # 是否支持嵌套（多层编码链）
    applicable_scenarios: List[str] = field(default_factory=lambda: ["sqli", "cmdi"])
    description: str = ""
    waf_relevance: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "EncodingRecipe":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Sample:
    """生成的测试样本 — seed 应用 encoding 后的产物"""
    sample_id: str                   # 确定性ID: "{seed_id}__{enc_ids}"
    seed_id: str
    scenario: str
    level: int
    category: str
    encoding_ids: List[str]          # 应用的编码链，如 ["url", "base64_cmd"]
    applied_payload: str             # 编码后的最终载荷
    transport: str                   # "api" | "direct" | "upload_direct" | "upload_waf"
    http_method: str = "GET"
    http_target: str = ""            # 如 "/sqli/level1.php"
    url_params: Dict[str, str] = field(default_factory=dict)
    expected_flag_pattern: str = ""
    waf: str = "on"                  # "on" | "off"

    # Upload专用
    filename: Optional[str] = None
    content_type: Optional[str] = None
    extra_fields: Dict[str, str] = field(default_factory=dict)

    # 执行状态
    status: str = "pending"          # pending | running | done | error | skipped
    retries: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None and v != [] and v != {}}

    @classmethod
    def from_dict(cls, d: dict) -> "Sample":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Result:
    """执行结果 — 一次攻击测试的完整记录"""
    run_id: str = ""                 # 运行批次ID
    sample_id: str = ""
    seed_id: str = ""
    scenario: str = ""
    level: int = 0
    category: str = ""
    encoding_ids: List[str] = field(default_factory=list)
    applied_payload: str = ""
    transport: str = ""
    waf_enabled: bool = True
    timestamp: str = ""
    execution_duration_ms: int = 0

    # WAF 响应
    waf_blocked: bool = False
    waf_rule_id: Optional[str] = None
    waf_rule_msg: Optional[str] = None
    waf_score_total: Optional[str] = None
    waf_score_sqli: Optional[str] = None
    waf_score_rce: Optional[str] = None
    http_status: int = 0

    # 攻击结果
    flag_captured: Optional[str] = None
    flag_verified: bool = False
    attack_successful: bool = False

    response_preview: str = ""
    error_message: Optional[str] = None
    retry_count: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None and v != [] and v != {}}

    @classmethod
    def from_dict(cls, d: dict) -> "Result":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_api_response(cls, data: dict, sample: "Sample", run_id: str = "") -> "Result":
        """从 API /api/attack.php 响应构建 Result"""
        flag = data.get("flag")
        return cls(
            run_id=run_id,
            sample_id=sample.sample_id,
            seed_id=sample.seed_id,
            scenario=sample.scenario,
            level=sample.level,
            category=sample.category,
            encoding_ids=sample.encoding_ids,
            applied_payload=sample.applied_payload,
            transport=sample.transport,
            waf_enabled=data.get("waf_enabled", True),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            waf_blocked=data.get("waf_blocked", False),
            waf_rule_id=data.get("waf_rule_id"),
            waf_rule_msg=data.get("waf_rule_msg"),
            http_status=data.get("http_status", 0),
            flag_captured=flag,
            flag_verified=_verify_flag(flag, sample.expected_flag_pattern),
            attack_successful=bool(flag and not data.get("waf_blocked")),
            response_preview=(data.get("response_preview") or "")[:500],
        )

    @classmethod
    def from_direct_response(cls, resp, sample: "Sample", run_id: str = "") -> "Result":
        """从直接 HTTP 响应（直连WAF）构建 Result"""
        import re
        body = resp.text or ""
        blocked = (resp.status_code == 403)
        flag = None
        m = re.search(r'flag\{([^}]+)\}', body)
        if m: flag = m.group(0)

        # 从响应头提取 WAF 评分
        waf_rule = resp.headers.get("X-WAF-Blocked", "")
        return cls(
            run_id=run_id,
            sample_id=sample.sample_id,
            seed_id=sample.seed_id,
            scenario=sample.scenario,
            level=sample.level,
            category=sample.category,
            encoding_ids=sample.encoding_ids,
            applied_payload=sample.applied_payload,
            transport=sample.transport,
            waf_enabled=(sample.waf == "on"),
            timestamp=datetime.now().isoformat(),
            waf_blocked=blocked,
            waf_rule_id=waf_rule if waf_rule else None,
            waf_score_total=resp.headers.get("X-WAF-Score-Total"),
            waf_score_sqli=resp.headers.get("X-WAF-Score-SQLi"),
            waf_score_rce=resp.headers.get("X-WAF-Score-RCE"),
            http_status=resp.status_code,
            flag_captured=flag,
            flag_verified=_verify_flag(flag, sample.expected_flag_pattern),
            attack_successful=bool(flag and not blocked),
            response_preview=body[:500],
        )

    @classmethod
    def from_upload_response(cls, body: str, http_status: int, shell_flag: str,
                             sample: "Sample", run_id: str = "") -> "Result":
        """从上传响应构建 Result"""
        import re
        blocked = (http_status == 403)
        flag = None
        m = re.search(r'flag\{([^}]+)\}', shell_flag or body)
        if m: flag = m.group(0)
        upload_ok = '上传成功' in body or '文件已暂存' in body

        return cls(
            run_id=run_id,
            sample_id=sample.sample_id,
            seed_id=sample.seed_id,
            scenario=sample.scenario,
            level=sample.level,
            category=sample.category,
            encoding_ids=sample.encoding_ids,
            applied_payload=f"file={sample.filename}",
            transport=sample.transport,
            waf_enabled=(sample.waf == "on"),
            timestamp=datetime.now().isoformat(),
            waf_blocked=blocked,
            http_status=http_status,
            flag_captured=flag,
            flag_verified=_verify_flag(flag, sample.expected_flag_pattern),
            attack_successful=bool(flag and not blocked),
            response_preview=body[:500] if not flag else f"UPLOAD_OK, shell_exec: {shell_flag[:200]}",
        )


def _verify_flag(flag: Optional[str], pattern: str) -> bool:
    """验证捕获的 flag 是否匹配期望模式"""
    if not flag or not pattern:
        return bool(flag)
    import re
    return bool(re.match(pattern, flag))
