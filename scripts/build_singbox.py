#!/usr/bin/env python3
"""
按下面 RULES 里写死的 ASN / CIDR 生成 sing-box rule-set 源文件（.json），
不再读取 Loon 的 .lsr。ASN 通过 RIPEstat 展开成当前宣告的全部 IPv4/IPv6 网段。

用法：
    python3 scripts/build_singbox.py sing-box
    （在 sing-box/ 下生成 TelegramNL.json 等，之后用 sing-box rule-set compile 编译成 .srs）

以后要增删 ASN 或网段，直接改下面的 RULES 即可。
"""
import ipaddress
import json
import sys
import time
import urllib.request
from pathlib import Path

RULES = {
    "TelegramNL": {
        "asn": [62041, 211157],
        "ip_cidr": ["5.28.192.0/18", "109.239.140.0/24"],
    },
    "TelegramSG": {
        "asn": [44907, 62014],
        "ip_cidr": [],
    },
    "TelegramUS": {
        "asn": [59930],
        "ip_cidr": [],
    },
}

# sing-box rule-set 源格式版本：2 适用于 sing-box 1.10 及以上
RULESET_VERSION = 2

RIPE_API = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"


def fetch_asn_prefixes(asn: int, retries: int = 3) -> list[str]:
    """从 RIPEstat 获取某 ASN 当前宣告的前缀。拿不到就抛异常，避免生成空规则。"""
    url = RIPE_API.format(asn=asn)
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "build_singbox/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.load(resp)
            prefixes = [p["prefix"] for p in data["data"]["prefixes"]]
            if not prefixes:
                raise RuntimeError(f"AS{asn} 返回了 0 个前缀")
            return prefixes
        except Exception as e:  # noqa: BLE001
            last_err = e
            print(f"  [重试 {attempt}/{retries}] AS{asn}: {e}", file=sys.stderr)
            time.sleep(5 * attempt)
    raise RuntimeError(f"获取 AS{asn} 失败：{last_err}")


def collapse(cidrs: list[str]) -> list[str]:
    """去重并合并相邻网段，v4 在前 v6 在后。"""
    v4, v6 = [], []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        (v4 if net.version == 4 else v6).append(net)
    return [str(n) for n in ipaddress.collapse_addresses(v4)] + \
           [str(n) for n in ipaddress.collapse_addresses(v6)]


def build(spec: dict, asn_fetcher=fetch_asn_prefixes) -> dict:
    cidrs = list(spec.get("ip_cidr", []))
    for asn in spec.get("asn", []):
        prefixes = asn_fetcher(asn)
        print(f"  AS{asn}: {len(prefixes)} 个前缀")
        cidrs.extend(prefixes)
    if not cidrs:
        raise RuntimeError("没有任何网段")
    return {"version": RULESET_VERSION, "rules": [{"ip_cidr": collapse(cidrs)}]}


def main() -> None:
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "sing-box")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, spec in RULES.items():
        print(f"生成 {name}")
        ruleset = build(spec)
        out = out_dir / f"{name}.json"
        out.write_text(json.dumps(ruleset, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"  -> {out}（ip_cidr {len(ruleset['rules'][0]['ip_cidr'])} 条）")


if __name__ == "__main__":
    main()
