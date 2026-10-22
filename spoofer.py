# =====================================================================
# Original work: https://github.com/revere-group/discord-badge-spoofer
# Copyright (c) 2026 Revere Group
# Modifications (UI & UX): Copyright (c) 2026 Bisho (BOSHRASAMUEL)
# =====================================================================
#!/usr/bin/env python3
"""
discord science spoofer - inflate the playtime and games-played badges.
UI Version - Discord Style (Responsive)
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
import webbrowser
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Sequence
import threading
import re
import tkinter.filedialog as filedialog

# محاولة استيراد مكتبة الواجهة
try:
    import customtkinter as ctk
except ImportError:
    print("[-] Please install customtkinter: pip install customtkinter")
    sys.exit(1)

# ==========================================
# الإعدادات الأصلية للسكريبت (Core Logic)
# ==========================================

ROOT = Path(__file__).resolve().parent
GAMES_FILE = ROOT.parent / "data" / "games.json"
STATE_FILE = ROOT / "science_state.json"

ME_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
SCIENCE_URL = "https://discord.com/api/v9/science"
PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"
GAMES_CDN_URL = "https://cdn.discordapp.com/detectables/games.json"

BATCH_SIZE = 50
BATCH_DELAY = 0.3
AUTH_MAX_AGE = 12 * 3600
DEBUG = False

CLIENT_VERSION = "1.0.9253"
CLIENT_BUILD_NUMBER = 594031
NATIVE_BUILD_NUMBER = 88414
OS_VERSION = "10.0.26200"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
    "Electron/42.7.1 Safari/537.36"
)

def _user_id_from_token(token: str) -> str:
    try:
        first = token.split(".", 1)[0]
        pad = "=" * (-len(first) % 4)
        return base64.b64decode(first + pad).decode("utf-8")
    except Exception:
        return ""

_FINGERPRINT_PS1 = r'''
param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;
  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }
  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);
  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@
if (!$Path) {
  if (!$ProcessId) { throw "Pass -Path <exe> or -ProcessId <pid>." }
  $Path = (Get-Process -Id $ProcessId).Path
}
if (!$Path) { throw "Could not resolve executable path." }
$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileSize = [UInt64]$fs.Length
  $readSize = [int][Math]::Min($fs.Length, 0x10000)
  $buf = [byte[]]::new($readSize)
  $read = $fs.Read($buf, 0, $readSize)
  if ($read -lt 0x40) { throw "File prefix is too small." }
  if ($read -ne $readSize) { [Array]::Resize([ref]$buf, $read) }
} finally {
  $fs.Dispose()
}
if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 0x3C)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }
$fh = $pe + 4
$sections = [BitConverter]::ToUInt16($buf, $fh + 2)
$timestamp = [BitConverter]::ToUInt32($buf, $fh + 4)
$optSize = [BitConverter]::ToUInt16($buf, $fh + 16)
$opt = $fh + 20
$isPe32Plus = [BitConverter]::ToUInt16($buf, $opt) -eq 0x20B
if (!$isPe32Plus) { throw "Discord only fingerprints PE32+." }
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)
$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])
$machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))
$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}
$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }
$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)
$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}
[Convert]::ToBase64String($out)
'''

def generate_fingerprint(user_id: str, path: str = "", pid: int = 0) -> str:
    if os.name != "nt":
        raise RuntimeError("fingerprint generation is windows-only")
    script = Path(tempfile.gettempdir()) / f"disc_fp_{uuid.uuid4().hex}.ps1"
    script.write_text(_FINGERPRINT_PS1, encoding="utf-8")
    try:
        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-UserId", user_id]
        args += (["-ProcessId", str(pid)] if pid else ["-Path", path])
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if result.returncode != 0:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(lines[-1] if lines else "powershell failed")
    out = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not out:
        raise RuntimeError("generator produced no output")
    return out[-1]

@dataclass
class State:
    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    fetched_at: int = 0
    used_games: list[str] = None
    total_games_claimed: int = 0
    total_hours_claimed: float = 0.0
    subscribed: bool = True
    joined_discord: bool = True

    def __post_init__(self) -> None:
        if self.used_games is None:
            self.used_games = []

    @classmethod
    def load(cls) -> "State":
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            state = cls(**{k: data.get(k, v) for k, v in cls().__dict__.items() if k != "used_games"})
            state.used_games = data.get("used_games", [])
            return state
        return cls()

    def save(self) -> None:
        STATE_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @property
    def is_stale(self) -> bool:
        return not self.analytics_token or (time.time() - self.fetched_at) > AUTH_MAX_AGE

    @property
    def has_cookie(self) -> bool:
        return bool(self.cookie.strip())

    @property
    def has_token(self) -> bool:
        return bool(self.token.strip())

def _local_props() -> dict:
    return {
        "os": "Windows", "browser": "Discord Client", "release_channel": "stable",
        "client_version": CLIENT_VERSION, "os_version": OS_VERSION, "os_arch": "x64",
        "app_arch": "x64", "system_locale": "en-GB", "has_client_mods": False,
        "browser_user_agent": USER_AGENT, "browser_version": "42.7.1",
        "os_sdk_version": "26200", "client_build_number": CLIENT_BUILD_NUMBER,
        "native_build_number": NATIVE_BUILD_NUMBER, "client_event_source": None,
        "client_app_state": "focused",
    }

def build_super_props(launch_signature: str, heartbeat_session: str) -> str:
    try:
        req = urllib.request.Request(PROPERTIES_URL, method="POST", data=b"{}",
                                     headers={"content-type": "application/json", "user-agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as response:
            props = json.loads(response.read().decode("utf-8"))["properties"]
    except Exception:
        props = _local_props()
    props["client_launch_id"] = str(uuid.uuid4())
    props["launch_signature"] = launch_signature
    props["client_heartbeat_session_id"] = heartbeat_session
    raw = json.dumps(props, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")

def _read_analytics_token(auth_token: str, super_props: str) -> str:
    req = urllib.request.Request(ME_URL, headers={
        "authorization": auth_token, "user-agent": USER_AGENT, "x-super-properties": super_props,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"token rejected ({exc.code})") from exc
    token = data.get("analytics_token")
    if not token:
        raise RuntimeError("no analytics_token in response")
    return token

def ensure_token(state: State, super_props: str) -> None:
    if not state.is_stale:
        return
    state.analytics_token = _read_analytics_token(state.token, super_props)
    state.fetched_at = int(time.time())
    state.save()

@dataclass(frozen=True)
class Session:
    heartbeat_session: str
    launch_signature: str
    super_props: str
    @classmethod
    def new(cls) -> "Session":
        hb = str(uuid.uuid4())
        sig = str(uuid.uuid4())
        return cls(hb, sig, build_super_props(sig, hb))

@dataclass(frozen=True)
class Game:
    id: str
    name: str
    exe: str

def _win_exe(game: dict) -> str:
    for entry in game.get("executables", []):
        if entry.get("os") == "win32" and entry.get("name"):
            return entry["name"]
    return "game.exe"

def _download_games() -> str:
    request = urllib.request.Request(GAMES_CDN_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
    try:
        GAMES_FILE.parent.mkdir(parents=True, exist_ok=True)
        GAMES_FILE.write_text(raw, encoding="utf-8")
    except OSError:
        pass
    return raw

def _parse_games(raw: str) -> list[Game]:
    data = json.loads(raw)
    games: list[Game] = []
    seen: set[str] = set()
    for entry in data:
        gid = str(entry.get("id", ""))
        if not gid.isdigit() or gid in seen:
            continue
        if not any(e.get("os") == "win32" and e.get("name") for e in entry.get("executables", [])):
            continue
        seen.add(gid)
        games.append(Game(gid, entry.get("name", "Unknown"), _win_exe(entry)))
    return games

def load_games() -> list[Game]:
    raw = ""
    if GAMES_FILE.exists():
        raw = GAMES_FILE.read_text(encoding="utf-8").strip()
    if raw:
        try:
            games = _parse_games(raw)
            if games:
                return games
        except (json.JSONDecodeError, ValueError):
            pass
    try:
        return _parse_games(_download_games())
    except Exception:
        return []

class ScienceClient:
    def __init__(self, state: State, session: Session) -> None:
        self.state = state
        self.session = session
        self._seq = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def build_launch(self, game: Game) -> dict:
        now = int(time.time() * 1000)
        props = {
            "client_track_timestamp": now,
            "client_heartbeat_session_id": self.session.heartbeat_session,
            "event_sequence_number": self._next_seq(),
            "game": game.name, "game_id": game.id, "verified": True, "elevated": False,
            "is_launcher": False, "game_platform": "desktop", "detection_method": "verified_game",
            "is_overlay_enabled": False, "is_overlay_game_enabled": True,
            "is_overlay_game_source": "OOP_DEFAULT_DATABASE", "fullscreen_type": "UNKNOWN",
            "hardware_display_count": 1, "overlay_method": "Disabled",
            "activity_status_enabled": True, "activity_status_shared_guilds": [],
            "current_user_status": "online", "game_detection_enabled": True,
            "executable_path": game.exe, "voice_channel_id": None, "voice_channel_type": None,
            "voice_channel_bitrate": None, "voice_channel_guild_id": None,
            "hidden_by_distributor": False, "game_metadata": None,
            "executable_fingerprint": self.state.fingerprint,
            "client_performance_cpu": None, "client_performance_memory": None,
            "cpu_core_count": None, "accessibility_features": 0, "rendered_locale": "en-GB",
            "launch_signature": self.session.launch_signature, "client_rtc_state": None,
            "client_app_state": "focused", "client_send_timestamp": now,
        }
        if not self.state.fingerprint:
            del props["executable_fingerprint"]
        return {"type": "launch_game", "properties": props}

    def build_heartbeat(self, game: Game, duration_ms: int, session_id: str,
                        initial: bool, final: bool, ts: int | None = None) -> dict:
        ts = int(time.time() * 1000) if ts is None else ts
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp": ts,
                "client_heartbeat_session_id": self.session.heartbeat_session,
                "event_sequence_number": self._next_seq(),
                "game_id": game.id, "game_name": game.name, "game_metadata": None,
                "game_executable": game.exe, "game_detection_enabled": True,
                "initial_heartbeat": initial, "final_heartbeat": final,
                "game_session_id": session_id, "duration_tracked_ms": duration_ms,
                "rtc_connection_id": None, "media_session_id": None,
                "launch_signature": self.session.launch_signature,
                "client_app_state": "focused", "client_send_timestamp": ts,
            },
        }

    def build_session(self, game: Game, duration_ms: int) -> list[dict]:
        sid = str(uuid.uuid4())
        now = int(time.time() * 1000)
        start = now - duration_ms
        if start < 0: start = now
        return [
            self.build_heartbeat(game, 0, sid, initial=True, final=False, ts=start),
            self.build_launch(game),
            self.build_heartbeat(game, duration_ms, sid, initial=False, final=True, ts=now),
        ]

    def post(self, events: Sequence[dict]) -> int:
        payload = {"token": self.state.analytics_token, "events": list(events)}
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "accept": "*/*", "accept-language": "en-GB",
            "authorization": self.state.token, "content-type": "application/json",
            "cookie": self.state.cookie, "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me", "user-agent": USER_AGENT,
            "x-debug-options": "bugReporterEnabled", "x-discord-locale": "en-GB",
            "x-discord-timezone": "Europe/Oslo", "x-super-properties": self.session.super_props,
        }
        request = urllib.request.Request(SCIENCE_URL, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return 0

def _chunked(items: Sequence[Game], size: int) -> Iterator[Sequence[Game]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]

class Spoofer:
    def __init__(self, client: ScienceClient) -> None:
        self.client = client

    def run(self, games: Sequence[Game], build_events) -> int:
        total = len(games)
        sent_ok = 0
        for request_no, chunk in enumerate(_chunked(games, BATCH_SIZE), start=1):
            events = []
            for game in chunk:
                events.extend(build_events(game))
            status = self.client.post(events)
            if status == 204:
                sent_ok += len(chunk)
                print(f"  [+] batch {request_no} · {sent_ok}/{total} games sent")
            elif status in (401, 403):
                print(f"  [-] batch {request_no} · [{status}] auth rejected · refresh cookie")
                return sent_ok
            else:
                print(f"  [!] batch {request_no} · [{status}] error")
            time.sleep(BATCH_DELAY)
        return sent_ok

# ==========================================
# الواجهة الرسومية (Discord Theme - Responsive)
# ==========================================

# ألوان ديسكورد
DISCORD_BG = "#313338"      
DISCORD_SIDEBAR = "#2B2D31" 
DISCORD_INPUT = "#1E1F22"   
BLURPLE = "#5865F2"         
BLURPLE_HOVER = "#4752C4"
TEXT_COLOR = "#DBDEE1"

class RedirectText:
    def __init__(self, textbox):
        self.textbox = textbox
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def write(self, string):
        clean_string = self.ansi_escape.sub('', string)
        self.textbox.configure(state="normal")
        self.textbox.insert("end", clean_string)
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def flush(self):
        pass

class DiscordSpooferUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Discord Spoofer - Revere Group")
        
        self.geometry("1000x700")
        self.minsize(800, 550) 
        
        self.configure(fg_color=DISCORD_BG)
        
        self.app_state = State.load()
        self.games = []
        self.is_running = False

        self.grid_columnconfigure(0, weight=0, minsize=320) 
        self.grid_columnconfigure(1, weight=1) 
        self.grid_rowconfigure(0, weight=1)

        self.setup_sidebar()
        self.setup_main_area()

        sys.stdout = RedirectText(self.console_output)
        
        # تشغيل تحميل الألعاب في الخلفية
        threading.Thread(target=self.load_games_async, daemon=True).start()
        
        # فتح رابط الـ GitHub تلقائياً عند بدء البرنامج (بعد ثانية عشان الواجهة تفتح الأول)
        self.after(1000, lambda: webbrowser.open("https://github.com/BOSHRASAMUEL/max-dis-badges"))

    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, corner_radius=0, fg_color=DISCORD_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.sidebar.grid_columnconfigure(0, weight=1) 

        self.logo_label = ctk.CTkLabel(self.sidebar, text="Spoofer Client", font=ctk.CTkFont(size=22, weight="bold"), text_color="white")
        self.logo_label.grid(row=0, column=0, pady=(25, 15), padx=20, sticky="w")

        self.token_label = ctk.CTkLabel(self.sidebar, text="Account Token", text_color=TEXT_COLOR, font=ctk.CTkFont(size=12, weight="bold"))
        self.token_label.grid(row=1, column=0, padx=20, sticky="w")
        self.token_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Paste Token...", fg_color=DISCORD_INPUT, border_width=0)
        self.token_entry.insert(0, self.app_state.token)
        self.token_entry.grid(row=2, column=0, padx=20, pady=(5, 15), sticky="ew")

        self.cookie_label = ctk.CTkLabel(self.sidebar, text="cf_clearance Cookie", text_color=TEXT_COLOR, font=ctk.CTkFont(size=12, weight="bold"))
        self.cookie_label.grid(row=3, column=0, padx=20, sticky="w")
        self.cookie_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Paste Cookie...", fg_color=DISCORD_INPUT, border_width=0)
        self.cookie_entry.insert(0, self.app_state.cookie)
        self.cookie_entry.grid(row=4, column=0, padx=20, pady=(5, 15), sticky="ew")

        self.fp_label = ctk.CTkLabel(self.sidebar, text="Executable Fingerprint", text_color=TEXT_COLOR, font=ctk.CTkFont(size=12, weight="bold"))
        self.fp_label.grid(row=5, column=0, padx=20, sticky="w")
        
        self.fp_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.fp_frame.grid(row=6, column=0, padx=20, pady=(5, 10), sticky="ew")
        self.fp_frame.grid_columnconfigure(0, weight=1)
        
        self.fp_entry = ctk.CTkEntry(self.fp_frame, placeholder_text="Game .exe Path", fg_color=DISCORD_INPUT, border_width=0)
        self.fp_entry.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        
        self.fp_browse_btn = ctk.CTkButton(self.fp_frame, text="📁", width=40, fg_color=DISCORD_INPUT, hover_color="#404249", command=self.browse_exe)
        self.fp_browse_btn.grid(row=0, column=1)

        self.fp_btn = ctk.CTkButton(self.sidebar, text="Generate Fingerprint", fg_color="#4E5058", hover_color="#686A70", command=self.generate_fingerprint)
        self.fp_btn.grid(row=7, column=0, padx=20, pady=(0, 15), sticky="ew")
        
        if self.app_state.fingerprint:
            print("[+] Fingerprint loaded from saved state.")

        self.settings_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.settings_frame.grid(row=8, column=0, padx=20, pady=10, sticky="ew")
        self.settings_frame.grid_columnconfigure(0, weight=1)
        self.settings_frame.grid_columnconfigure(1, weight=1)

        self.games_label = ctk.CTkLabel(self.settings_frame, text="Games:", text_color=TEXT_COLOR, font=ctk.CTkFont(size=12, weight="bold"))
        self.games_label.grid(row=0, column=0, sticky="w", pady=(0, 2))
        self.games_entry = ctk.CTkEntry(self.settings_frame, placeholder_text="All", fg_color=DISCORD_INPUT, border_width=0)
        self.games_entry.grid(row=1, column=0, padx=(0, 5), sticky="ew")

        self.hours_label = ctk.CTkLabel(self.settings_frame, text="Hours:", text_color=TEXT_COLOR, font=ctk.CTkFont(size=12, weight="bold"))
        self.hours_label.grid(row=0, column=1, sticky="w", pady=(0, 2))
        self.hours_entry = ctk.CTkEntry(self.settings_frame, placeholder_text="1", fg_color=DISCORD_INPUT, border_width=0)
        self.hours_entry.grid(row=1, column=1, padx=(5, 0), sticky="ew")

        self.start_btn = ctk.CTkButton(self.sidebar, text="START SPOOFING", fg_color=BLURPLE, hover_color=BLURPLE_HOVER, height=45, font=ctk.CTkFont(size=14, weight="bold"), command=self.start_spoofing)
        self.start_btn.grid(row=9, column=0, padx=20, pady=(20, 10), sticky="ew")

        self.save_btn = ctk.CTkButton(self.sidebar, text="Save Auth Settings", fg_color="transparent", border_width=1, border_color="#4E5058", hover_color="#404249", command=self.save_settings)
        self.save_btn.grid(row=10, column=0, padx=20, pady=(0, 10), sticky="ew")

        # --- زرار التواصل الجديد ---
        self.contact_btn = ctk.CTkButton(self.sidebar, text="Contact Me", fg_color="transparent", border_width=1, border_color="#4E5058", hover_color="#404249", command=lambda: webbrowser.open("https://guns.lol/bisho"))
        self.contact_btn.grid(row=11, column=0, padx=20, pady=(0, 20), sticky="ew")

    def setup_main_area(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=(10, 20), pady=20, sticky="nsew")
        
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.status_label = ctk.CTkLabel(self.main_frame, text="Console Logs", font=ctk.CTkFont(size=16, weight="bold"), text_color="white")
        self.status_label.grid(row=0, column=0, pady=(0, 10), sticky="w")

        self.console_output = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Consolas", size=13), fg_color=DISCORD_INPUT, text_color="#B5BAC1", corner_radius=8)
        self.console_output.grid(row=1, column=0, sticky="nsew")
        self.console_output.insert("end", "Welcome to Discord Spoofer UI!\n")
        self.console_output.insert("end", "1. Fill your Token and Cookie.\n")
        self.console_output.insert("end", "2. (Optional) Generate Fingerprint.\n")
        self.console_output.insert("end", "3. Click START.\n\n")
        self.console_output.configure(state="disabled")

    def load_games_async(self):
        print("[*] Downloading game list from Discord...")
        self.games = load_games()
        if self.games:
            print(f"[+] Successfully loaded {len(self.games)} games.")
        else:
            print("[-] Failed to load game list. Check your internet.")

    def browse_exe(self):
        filepath = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
        if filepath:
            self.fp_entry.delete(0, "end")
            self.fp_entry.insert(0, filepath)

    def save_settings(self):
        self.app_state.token = self.token_entry.get().strip()
        self.app_state.cookie = self.cookie_entry.get().strip()
        self.app_state.save()
        print("[+] Auth settings saved to science_state.json")

    def generate_fingerprint(self):
        path = self.fp_entry.get().strip().strip('"')
        if not path or not os.path.exists(path):
            print("[-] Please select a valid .exe file first.")
            return
            
        uid = _user_id_from_token(self.app_state.token)
        if not uid:
            print("[-] Invalid Token. Please save a valid token first.")
            return

        print(f"[*] Generating fingerprint for user {uid}...")
        print("[*] This may take a few seconds via PowerShell...")
        
        try:
            fp = generate_fingerprint(uid, path=path)
            self.app_state.fingerprint = fp
            self.app_state.save()
            print(f"[+] Fingerprint generated successfully ({len(fp)} chars) and saved!")
        except Exception as e:
            print(f"[-] Error generating fingerprint: {e}")

    def start_spoofing(self):
        if self.is_running:
            return
            
        self.save_settings()
        
        if not self.app_state.token or not self.app_state.cookie:
            print("[-] Token and Cookie are required to start!")
            return

        if not self.games:
            print("[-] Games not loaded yet. Please wait...")
            return

        try:
            games_count_str = self.games_entry.get().strip()
            games_count = int(games_count_str) if games_count_str else len(self.games)
            
            hours_str = self.hours_entry.get().strip()
            hours = float(hours_str) if hours_str else 1.0
        except ValueError:
            print("[-] Please enter valid numbers for Games and Hours.")
            return

        self.is_running = True
        self.start_btn.configure(state="disabled", text="SPOOFING...", fg_color="#4E5058")

        thread = threading.Thread(target=self.run_spoofer_logic, args=(games_count, hours))
        thread.daemon = True
        thread.start()

    def run_spoofer_logic(self, games_count, hours):
        try:
            print(f"\n[*] Initializing session...")
            session = Session.new()
            client = ScienceClient(self.app_state, session)
            
            if self.app_state.is_stale:
                print("[*] Validating token & fetching analytics...")
                ensure_token(self.app_state, session.super_props)
                print("[+] Auth validated.")

            app_instance = type('App', (), {'state': self.app_state, 'games': self.games})()
            def _select_games(self, count):
                available_ids = {g.id for g in self.games}
                unused_ids = [g.id for g in self.games if g.id not in self.state.used_games]
                used_ids = [gid for gid in self.state.used_games if gid in available_ids]
                if len(unused_ids) >= count:
                    selected_ids = unused_ids[:count]
                else:
                    selected_ids = unused_ids
                    if used_ids:
                        remaining = count - len(selected_ids)
                        rotated = used_ids[remaining:] + used_ids[:remaining]
                        selected_ids.extend(rotated[:remaining])
                self.state.used_games = [gid for gid in self.state.used_games if gid not in selected_ids] + selected_ids
                id_map = {g.id: g for g in self.games}
                return [id_map[gid] for gid in selected_ids if gid in id_map]

            selected = _select_games(app_instance, min(games_count, len(self.games)))
            
            duration_ms = int(hours * 3600 * 1000)
            print(f"[*] Claiming {hours}h on {len(selected)} games...")
            
            spoofer_obj = Spoofer(client)
            ok = spoofer_obj.run(selected, lambda g: client.build_session(g, duration_ms))
            
            self.app_state.total_games_claimed += ok
            self.app_state.total_hours_claimed += ok * hours
            self.app_state.save()
            
            print(f"\n[+] Process Completed! Total claimed: {ok} games ({ok * hours}h).")
            
        except Exception as e:
            print(f"[-] Critical Error: {e}")
        finally:
            self.is_running = False
            self.start_btn.configure(state="normal", text="START SPOOFING", fg_color=BLURPLE)

if __name__ == "__main__":
    app = DiscordSpooferUI()
    app.mainloop()