"""Inspect the built APK, without installing it or reading user profiles."""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import zipfile
from pathlib import Path


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def launcher_resources(apk_path, asset_names, aapt2):
    expected_apis = {"21", "26", "33"}
    if aapt2 is None:
        paths = {match[1]: name for name in asset_names
                 if (match := re.fullmatch(r"res/mipmap-[^/]+-v(21|26|33)/ic_launcher\.xml", name))}
    else:
        resources = subprocess.check_output(
            [str(aapt2), "dump", "resources", str(apk_path)], encoding="utf-8")
        marker = re.search(r"(?m)^    resource \S+ mipmap/ic_launcher[ \t]*$", resources)
        assert marker is not None, "missing mipmap/ic_launcher resource"
        values = resources[marker.end():].split("\n    resource ", 1)[0]
        paths = {api or "21": name for api, name in re.findall(
            r"(?m)^[ \t]+\(anydpi(?:-v(21|26|33))?\) \(file\) (\S+\.xml) type=XML$", values)}
    assert set(paths) == expected_apis, f"missing launcher XML for API {expected_apis - paths.keys()}"
    assert set(paths.values()) <= asset_names, "launcher XML missing from APK"
    return sorted(paths.values())


parser = argparse.ArgumentParser()
parser.add_argument("apk", type=Path)
parser.add_argument("aar", type=Path)
parser.add_argument("report", type=Path)
parser.add_argument("--runtime-label", default="1.14.4-silikbox.2")
parser.add_argument("--aapt2", type=Path, help="Inspect launcher resources even when APK paths are shortened")
args = parser.parse_args()
with zipfile.ZipFile(args.apk) as apk, zipfile.ZipFile(args.aar) as aar:
    libraries = [n for n in apk.namelist() if n.startswith("lib/") and n.endswith(".so")]
    assert libraries == ["lib/arm64-v8a/libgojni.so"], libraries
    library = apk.read(libraries[0])
    assert library == aar.read("jni/arm64-v8a/libgojni.so"), "APK contains a different AAR"
    assert library[:6] == b"\x7fELF\x02\x01", "expected ELF64 little-endian"
    assert struct.unpack_from("<H", library, 18)[0] == 183, "expected AArch64"
    offset = struct.unpack_from("<Q", library, 32)[0]
    entry_size, count = struct.unpack_from("<HH", library, 54)
    alignments = []
    for index in range(count):
        header = struct.unpack_from("<IIQQQQQQ", library, offset + index * entry_size)
        if header[0] == 1:
            alignments.append(header[7])
    assert alignments and min(alignments) >= 16384, alignments
    assert args.runtime_label.encode() in library, "missing expected runtime label"
    assert b"silikbox-bootstrap" in library, "missing endpoint DNS fallback transport"
    forbidden = ("223.5.5.5", "223.6.6.6", "dns.alidns.com")
    for name in apk.namelist():
        if name.endswith((".dex", ".so", ".arsc", ".xml")):
            data = apk.read(name)
            for address in forbidden:
                assert address.encode() not in data and address.encode("utf-16le") not in data, f"retired DNS endpoint in {name}"
    assets = ["assets/sing-box/geoip.db.xz", "assets/sing-box/geosite.db.xz",
              "assets/sing-box/geoip.version.txt", "assets/sing-box/geosite.version.txt",
              "assets/yacd.zip", "assets/yacd.version.txt"]
    # The source tree uses version files without a .txt suffix in some upstream builds.
    asset_names = set(apk.namelist())
    launcher_xmls = launcher_resources(args.apk, asset_names, args.aapt2)
    checked_assets = []
    for name in assets:
        actual = name if name in asset_names else name.removesuffix(".txt")
        assert actual in asset_names and len(apk.read(actual)) > 0, name
        checked_assets.append(actual)
    report = {
        "apk": args.apk.name,
        "apk_sha256": sha256(args.apk.read_bytes()),
        "aar_sha256": sha256(args.aar.read_bytes()),
        "library_sha256": sha256(library),
        "aar_library_matches_apk": True,
        "retired_dns_endpoints_absent": True,
        "bootstrap_dns_policy": ["Google DoH", "Cloudflare ordinary DNS", "Android system DNS"],
        "abi": "arm64-v8a", "runtime_label": args.runtime_label,
        "elf_load_alignments": alignments,
        "bundled_assets": checked_assets,
        "launcher_xmls": launcher_xmls,
        "scope": "static artifact validation; no Android runtime or VPN acceptance",
    }
args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
