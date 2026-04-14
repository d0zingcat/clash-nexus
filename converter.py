#!/usr/bin/env python3
"""Clash (mihomo) YAML -> Loon .conf converter."""

import argparse
import re
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Unit 2: [General]
# ---------------------------------------------------------------------------


def convert_general(config: dict) -> str:
    lines = ["[General]"]

    # skip-proxy / bypass-tun defaults
    lines.append(
        "skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,e.crashlynatics.com"
    )
    lines.append(
        "bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32"
    )

    # DNS -------------------------------------------------------------------
    dns_cfg = config.get("dns", {})

    # Collect plain UDP nameservers
    udp_servers = []
    for ns in dns_cfg.get("nameserver", []):
        ns = str(ns).strip()
        if (
            ns.startswith("https://")
            or ns.startswith("tls://")
            or ns.startswith("quic://")
        ):
            continue
        udp_servers.append(ns)
    if udp_servers:
        lines.append(f"dns-server = system,{','.join(udp_servers)}")
    else:
        lines.append("dns-server = system")

    # Collect DoH servers from fallback
    doh_servers = []
    for fb in dns_cfg.get("fallback", []):
        fb = str(fb).strip().strip("'\"")
        if fb.startswith("https://"):
            doh_servers.append(fb)
    if doh_servers:
        lines.append(f"doh-server = {','.join(doh_servers)}")

    # ip-mode
    ipv6 = config.get("ipv6", dns_cfg.get("ipv6", False))
    lines.append(f"ip-mode = {'dual' if ipv6 else 'ipv4-only'}")

    # allow-wifi-access
    if config.get("allow-lan", False):
        lines.append("allow-wifi-access = true")
        lines.append("wifi-access-http-port = 7222")
        lines.append("wifi-access-socks5-port = 7221")

    # proxy-test-url / test-timeout
    lines.append("proxy-test-url = http://www.gstatic.com/generate_204")
    lines.append("internet-test-url = http://wifi.vivo.com.cn/generate_204")
    lines.append("test-timeout = 5")

    # resource-parser (SubStore)
    lines.append(
        "resource-parser = https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/backend/dist/sub-store-parser.loon.min.js"
    )

    # real-ip from fake-ip-filter
    fip = dns_cfg.get("fake-ip-filter", [])
    real_ips = [str(f).strip() for f in fip if str(f).strip() not in ("*",)]
    if real_ips:
        lines.append(f"real-ip = {','.join(real_ips)}")

    # hijack-dns
    lines.append("hijack-dns = *:53")

    # udp-fallback-mode
    lines.append("udp-fallback-mode = REJECT")
    lines.append("disable-stun = true")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unit 3: [Proxy]
# ---------------------------------------------------------------------------


def _convert_trojan(p: dict) -> str:
    name = p["name"]
    server = p["server"]
    port = p["port"]
    password = p.get("password", "")
    parts = [f'{name} = trojan,{server},{port},"{password}"']

    if p.get("skip-cert-verify"):
        parts.append("skip-cert-verify=true")
    sni = p.get("sni")
    if sni:
        parts.append(f"sni={sni}")

    transport = p.get("network", "tcp")
    if transport == "ws":
        parts.append("transport=ws")
        ws_opts = p.get("ws-opts", {})
        if ws_opts.get("path"):
            parts.append(f"path={ws_opts['path']}")
        headers = ws_opts.get("headers", {})
        if headers.get("Host"):
            parts.append(f"host={headers['Host']}")

    parts.append(f"udp={'true' if p.get('udp', True) else 'false'}")
    return ",".join(parts)


def _convert_ss(p: dict) -> str:
    name = p["name"]
    server = p["server"]
    port = p["port"]
    cipher = p.get("cipher", "aes-256-gcm")
    password = p.get("password", "")
    parts = [f'{name} = Shadowsocks,{server},{port},{cipher},"{password}"']
    parts.append(f"fast-open={'true' if p.get('fast-open', False) else 'false'}")
    parts.append(f"udp={'true' if p.get('udp', True) else 'false'}")
    return ",".join(parts)


def _convert_vmess(p: dict) -> str:
    name = p["name"]
    server = p["server"]
    port = p["port"]
    cipher = p.get("cipher", "auto")
    uuid = p.get("uuid", "")
    parts = [f'{name} = vmess,{server},{port},{cipher},"{uuid}"']

    transport = p.get("network", "tcp")
    parts.append(f"transport={transport}")
    parts.append(f"alterId={p.get('alterId', 0)}")

    if transport == "ws":
        ws_opts = p.get("ws-opts", {})
        if ws_opts.get("path"):
            parts.append(f"path={ws_opts['path']}")
        headers = ws_opts.get("headers", {})
        if headers.get("Host"):
            parts.append(f"host={headers['Host']}")
    elif transport == "http":
        http_opts = p.get("http-opts", {})
        paths = http_opts.get("path", ["/"])
        parts.append(f"path={paths[0] if paths else '/'}")
        hosts = http_opts.get("host", [])
        if hosts:
            parts.append(f"host={hosts[0]}")

    tls = p.get("tls", False)
    parts.append(f"over-tls={'true' if tls else 'false'}")
    if tls:
        sni = p.get("servername") or p.get("sni", "")
        if sni:
            parts.append(f"sni={sni}")
        if p.get("skip-cert-verify"):
            parts.append("skip-cert-verify=true")

    parts.append(f"udp={'true' if p.get('udp', True) else 'false'}")
    return ",".join(parts)


def _convert_vless(p: dict) -> str:
    name = p["name"]
    server = p["server"]
    port = p["port"]
    uuid = p.get("uuid", "")
    parts = [f'{name} = VLESS,{server},{port},"{uuid}"']

    transport = p.get("network", "tcp")
    parts.append(f"transport={transport}")

    flow = p.get("flow", "")
    if flow:
        parts.append(f"flow={flow}")

    reality_opts = p.get("reality-opts", {})
    if reality_opts:
        pub_key = reality_opts.get("public-key", "")
        if pub_key:
            parts.append(f'public-key="{pub_key}"')
        short_id = reality_opts.get("short-id", "")
        if short_id:
            parts.append(f"short-id={short_id}")

    if transport == "ws":
        ws_opts = p.get("ws-opts", {})
        if ws_opts.get("path"):
            parts.append(f"path={ws_opts['path']}")
        headers = ws_opts.get("headers", {})
        if headers.get("Host"):
            parts.append(f"host={headers['Host']}")

    tls = p.get("tls", False)
    parts.append(f"over-tls={'true' if tls else 'false'}")
    if tls or reality_opts:
        sni = p.get("servername") or p.get("sni", "")
        if sni:
            parts.append(f"sni={sni}")
        if p.get("skip-cert-verify"):
            parts.append("skip-cert-verify=true")

    parts.append(f"udp={'true' if p.get('udp', True) else 'false'}")
    return ",".join(parts)


def _convert_hysteria2(p: dict) -> str:
    name = p["name"]
    server = p["server"]
    port = p["port"]
    password = p.get("password", "")
    parts = [f'{name} = Hysteria2,{server},{port},"{password}"']
    if p.get("skip-cert-verify"):
        parts.append("skip-cert-verify=true")
    sni = p.get("sni", "")
    if sni:
        parts.append(f"sni={sni}")
    parts.append(f"udp={'true' if p.get('udp', True) else 'false'}")
    return ",".join(parts)


PROXY_CONVERTERS = {
    "trojan": _convert_trojan,
    "ss": _convert_ss,
    "vmess": _convert_vmess,
    "vless": _convert_vless,
    "hysteria2": _convert_hysteria2,
}


def convert_proxies(proxies: list) -> str:
    lines = ["[Proxy]"]
    for p in proxies:
        ptype = p.get("type", "")
        converter = PROXY_CONVERTERS.get(ptype)
        if converter:
            lines.append(converter(p))
        else:
            lines.append(
                f"# [WARNING] Unsupported proxy type '{ptype}': {p.get('name', '?')}"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unit 3b: [Proxy Chain]
# ---------------------------------------------------------------------------


def convert_proxy_chains(proxies: list) -> tuple[str, dict]:
    """Returns (section text, {original_name: chain_name} mapping)."""
    lines = ["[Proxy Chain]"]
    chain_map: dict[str, str] = {}
    for p in proxies:
        dialer = p.get("dialer-proxy")
        if dialer:
            name = p["name"]
            chain_name = f"{name} (Chain)"
            lines.append(f"{chain_name} = {name},{dialer},udp=true")
            chain_map[name] = chain_name
    return "\n".join(lines), chain_map


# ---------------------------------------------------------------------------
# Unit 4: [Remote Proxy] + [Remote Filter]
# ---------------------------------------------------------------------------


def convert_remote_proxy(providers: dict) -> str:
    lines = ["[Remote Proxy]"]
    for alias, cfg in providers.items():
        url = cfg.get("url", "")
        lines.append(f"{alias} = {url}")
        ef = cfg.get("exclude-filter")
        if ef:
            lines.append(
                f"# [NOTE] exclude-filter for {alias}: {ef}  (apply via Remote Filter if needed)"
            )
    return "\n".join(lines)


def convert_remote_filters(groups: list, providers: dict) -> str:
    lines = ["[Remote Filter]"]
    provider_names = list(providers.keys())

    for g in groups:
        uses = g.get("use", [])
        if not uses:
            continue
        name = g["name"]
        filt = g.get("filter", "")
        filter_name = f"{name}_Filter"

        # Build source list (only providers this group references)
        sources = ",".join(uses)

        if filt:
            lines.append(f'{filter_name} = NameRegex,{sources},FilterKey = "{filt}"')
        else:
            # No filter — use a regex that excludes info nodes
            lines.append(
                f'{filter_name} = NameRegex,{sources},FilterKey = "^(?i)(?!.*(traffic|expire|剩余|到期)).*$"'
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unit 5: [Proxy Group]
# ---------------------------------------------------------------------------


def convert_proxy_groups(groups: list, chain_map: dict) -> str:
    lines = ["[Proxy Group]"]

    for g in groups:
        name = g["name"]
        gtype = g.get("type", "select")

        # Collect members
        members = []
        for px in g.get("proxies", []):
            # Replace with chain name if this proxy has a dialer-proxy chain
            members.append(chain_map.get(px, px))

        # If group uses providers, add the filter name
        if g.get("use"):
            filter_name = f"{name}_Filter"
            members.append(filter_name)

        member_str = ",".join(members)

        if gtype == "select":
            lines.append(f"{name} = select,{member_str}")

        elif gtype == "url-test":
            url = g.get("url", "http://www.gstatic.com/generate_204")
            interval = g.get("interval", 600)
            tolerance = g.get("tolerance", 100)
            lines.append(
                f"{name} = url-test,{member_str},url = {url},interval = {interval},tolerance = {tolerance}"
            )

        elif gtype == "fallback":
            url = g.get("url", "http://www.gstatic.com/generate_204")
            interval = g.get("interval", 600)
            timeout = g.get("timeout", 5000)
            lines.append(
                f"{name} = fallback,{member_str},url = {url},interval = {interval},max-timeout = {timeout}"
            )

        elif gtype == "load-balance":
            url = g.get("url", "http://www.gstatic.com/generate_204")
            interval = g.get("interval", 600)
            strategy = g.get("strategy", "consistent-hashing")
            algo_map = {
                "consistent-hashing": "pcc",
                "round-robin": "Round-Robin",
            }
            algo = algo_map.get(strategy, "pcc")
            lines.append(
                f"{name} = load-balance,{member_str},url = {url},interval = {interval},algorithm = {algo}"
            )

        elif gtype == "relay":
            # relay -> Proxy Chain (handled separately), skip here with a note
            lines.append(
                f"# [NOTE] relay group '{name}' should be configured in [Proxy Chain] section"
            )

        else:
            lines.append(f"# [WARNING] Unknown group type '{gtype}': {name}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unit 6: [Rule] + [Remote Rule]
# ---------------------------------------------------------------------------


def _convert_rule_provider_url(url: str) -> str:
    """Convert a Clash rule-provider URL to Loon-compatible format."""
    # blackmatrix7: rule/Clash/ -> rule/Loon/, .yaml -> .list
    if "blackmatrix7" in url and "rule/Clash/" in url:
        url = url.replace("rule/Clash/", "rule/Loon/")
        url = re.sub(r"\.yaml$", ".list", url)
    elif "ACL4SSR" in url:
        # ACL4SSR Clash Providers are .yaml, try .list
        url = re.sub(r"\.yaml$", ".list", url)
    return url


def convert_rules_and_remote_rules(
    rules: list, rule_providers: dict
) -> tuple[str, str]:
    local_lines = ["[Rule]"]
    remote_lines = ["[Remote Rule]"]

    # Build provider URL map
    provider_urls: dict[str, str] = {}
    for rp_name, rp_cfg in rule_providers.items():
        provider_urls[rp_name] = rp_cfg.get("url", "")

    seen_remote = set()

    for rule_str in rules:
        if rule_str is None:
            continue
        rule_str = str(rule_str).strip()
        if not rule_str or rule_str.startswith("#"):
            continue

        parts = [p.strip() for p in rule_str.split(",")]
        if len(parts) < 2:
            continue

        rule_type = parts[0].upper()

        if rule_type == "RULE-SET":
            rp_name = parts[1]
            policy = parts[2] if len(parts) > 2 else "PROXY"
            raw_url = provider_urls.get(rp_name, "")
            if not raw_url:
                local_lines.append(f"# [WARNING] rule-provider '{rp_name}' not found")
                continue
            loon_url = _convert_rule_provider_url(raw_url)
            if rp_name not in seen_remote:
                if "ACL4SSR" in raw_url:
                    remote_lines.append(
                        f"# [NOTE] ACL4SSR URL — verify Loon compatibility"
                    )
                remote_lines.append(f"{loon_url},policy={policy},enabled=true")
                seen_remote.add(rp_name)

        elif rule_type == "MATCH":
            policy = parts[1] if len(parts) > 1 else "DIRECT"
            local_lines.append(f"FINAL,{policy}")

        else:
            # DOMAIN, DOMAIN-SUFFIX, IP-CIDR, GEOIP, etc. — pass through
            local_lines.append(",".join(parts))

    return "\n".join(local_lines), "\n".join(remote_lines)


# ---------------------------------------------------------------------------
# Unit 7: [Host]
# ---------------------------------------------------------------------------


def convert_hosts(hosts: dict) -> str:
    lines = ["[Host]"]
    for domain, target in hosts.items():
        lines.append(f"{domain} = {target}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main assembly
# ---------------------------------------------------------------------------


def convert(config: dict) -> str:
    sections = []

    # [General]
    sections.append(convert_general(config))

    # [Proxy]
    proxies = config.get("proxies", [])
    sections.append(convert_proxies(proxies))

    # [Proxy Chain]
    proxy_chain_text, chain_map = convert_proxy_chains(proxies)
    sections.append(proxy_chain_text)

    # [Remote Proxy]
    providers = config.get("proxy-providers", {})
    sections.append(convert_remote_proxy(providers))

    # [Remote Filter]
    groups = config.get("proxy-groups", [])
    sections.append(convert_remote_filters(groups, providers))

    # [Proxy Group]
    sections.append(convert_proxy_groups(groups, chain_map))

    # [Rule] + [Remote Rule]
    rules = config.get("rules", [])
    rule_providers = config.get("rule-providers", {})
    rule_text, remote_rule_text = convert_rules_and_remote_rules(rules, rule_providers)
    sections.append(rule_text)
    sections.append(remote_rule_text)

    # [Host]
    hosts = config.get("hosts", {})
    if hosts:
        sections.append(convert_hosts(hosts))

    # Empty stubs for sections Loon expects but we don't populate
    sections.append("[Rewrite]")
    sections.append("[Remote Rewrite]")
    sections.append("[Script]")
    sections.append("[Remote Script]")
    sections.append("[Plugin]")
    sections.append("[MITM]")

    return "\n\n".join(sections) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Convert Clash YAML config to Loon .conf"
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="input/all-in-one.yaml",
        help="Path to Clash YAML config file (default: input/all-in-one.yaml)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="output/loon.conf",
        help="Output Loon config file path (default: output/loon.conf)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not config or not isinstance(config, dict):
        print(
            "Warning: empty or invalid YAML, generating skeleton config",
            file=sys.stderr,
        )
        config = {}

    result = convert(config)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(result)

    print(f"Converted: {input_path} -> {output_path}")


if __name__ == "__main__":
    main()
