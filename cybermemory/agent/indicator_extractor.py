"""
Indicator of Compromise (IOC) and artifact extractor.
Extracts IPs, domains, URLs, hashes, processes, paths, registry keys, and users from text and logs.
"""

import re
from typing import Set, Dict, Any
from cybermemory.models import ExtractedIndicators

# Regex patterns for cybersecurity entities
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
DOMAIN_PATTERN = re.compile(r"\b(?!(?:https?|ftp|ldap)://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|cc|xyz|co|io|local|corp|internal)\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"\b(?:https?|ftp|ldap)://[^\s<>\"'{}|\\^`\[\]]+\b", re.IGNORECASE)
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
WINDOWS_PATH_PATTERN = re.compile(r"\b[a-zA-Z]:\\(?:[a-zA-Z0-9_\.\-]+\\)*[a-zA-Z0-9_\.\-]+\b")
LINUX_PATH_PATTERN = re.compile(r"(?:\/(?:var|tmp|etc|opt|home|bin|usr)\/[a-zA-Z0-9_\.\-\/]+)")
REGISTRY_PATTERN = re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\\.\-]+", re.IGNORECASE)
PROCESS_PATTERN = re.compile(r"\b[a-zA-Z0-9_\-]+\.(?:exe|dll|vbs|ps1|bat|sh|py|aspx|jsp)\b", re.IGNORECASE)
KNOWN_LINUX_PROCS = {"java", "curl", "wget", "nc", "ncat", "bash", "sh", "sshd", "tomcat"}
USER_ACCOUNT_PATTERN = re.compile(r"\b(?:CORP\\[a-zA-Z0-9_\.\-]+|[a-zA-Z0-9_\.\-]+@[a-zA-Z0-9_\.\-]+\.[a-zA-Z]{2,}|IIS APPPOOL\\[a-zA-Z0-9_\.\-]+|svc_[a-zA-Z0-9_\-]+)\b")
HOSTNAME_PATTERN = re.compile(r"\b(?:WS-[A-Z0-9\-]+|SRV-[A-Z0-9\-]+|DC-[A-Z0-9\-]+|FS-[A-Z0-9\-]+|PRINT-[A-Z0-9\-]+)(?:\.corp\.local)?\b", re.IGNORECASE)


class IndicatorExtractor:
    """Extracts cybersecurity indicators from unstructured log and alert text."""

    @classmethod
    def extract_from_text(cls, text: str) -> ExtractedIndicators:
        if not text:
            return ExtractedIndicators()

        # IPs
        raw_ips = IPV4_PATTERN.findall(text)
        # Filter out 0.0.0.0 or standard broadcast
        filtered_ips = sorted(list({ip for ip in raw_ips if not ip.startswith("0.") and not ip.startswith("255.")}))

        # URLs
        urls = sorted(list(set(URL_PATTERN.findall(text))))

        # Domains (filter out domains that are already inside URLs or IP-like)
        raw_domains = DOMAIN_PATTERN.findall(text)
        domains = sorted(list({
            d.lower() for d in raw_domains
            if not IPV4_PATTERN.match(d) and not d.endswith(".exe") and not d.endswith(".dll")
        }))

        # Hashes
        sha256 = SHA256_PATTERN.findall(text)
        sha1 = [h for h in SHA1_PATTERN.findall(text) if h not in sha256]
        md5 = [h for h in MD5_PATTERN.findall(text) if h not in sha256 and h not in sha1]
        all_hashes = sorted(list(set(sha256 + sha1 + md5)))

        # Process names
        procs: Set[str] = set(PROCESS_PATTERN.findall(text))
        for token in text.split():
            clean_token = token.strip("(),;:'\"[]")
            if clean_token in KNOWN_LINUX_PROCS:
                procs.add(clean_token)
        sorted_procs = sorted(list(procs))

        # File paths
        win_paths = WINDOWS_PATH_PATTERN.findall(text)
        nix_paths = LINUX_PATH_PATTERN.findall(text)
        paths = sorted(list(set(win_paths + nix_paths)))

        # Registry keys
        reg_keys = sorted(list(set(REGISTRY_PATTERN.findall(text))))

        # User accounts
        users = sorted(list(set(USER_ACCOUNT_PATTERN.findall(text))))

        # Hostnames
        hosts = sorted(list(set(HOSTNAME_PATTERN.findall(text))))

        return ExtractedIndicators(
            ip_addresses=filtered_ips,
            domains=domains,
            urls=urls,
            file_hashes=all_hashes,
            process_names=sorted_procs,
            file_paths=paths,
            registry_keys=reg_keys,
            user_accounts=users,
            hostnames=hosts
        )

    @classmethod
    def merge_indicators(cls, *indicators: ExtractedIndicators) -> ExtractedIndicators:
        merged = ExtractedIndicators()
        for ind in indicators:
            merged.ip_addresses = sorted(list(set(merged.ip_addresses + ind.ip_addresses)))
            merged.domains = sorted(list(set(merged.domains + ind.domains)))
            merged.urls = sorted(list(set(merged.urls + ind.urls)))
            merged.file_hashes = sorted(list(set(merged.file_hashes + ind.file_hashes)))
            merged.process_names = sorted(list(set(merged.process_names + ind.process_names)))
            merged.file_paths = sorted(list(set(merged.file_paths + ind.file_paths)))
            merged.registry_keys = sorted(list(set(merged.registry_keys + ind.registry_keys)))
            merged.user_accounts = sorted(list(set(merged.user_accounts + ind.user_accounts)))
            merged.hostnames = sorted(list(set(merged.hostnames + ind.hostnames)))
        return merged

