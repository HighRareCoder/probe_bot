#!/usr/bin/env python3
"""
Скачивание sing-box с GitHub Releases под текущую ОС/архитектуру.
Релиз зафиксирован в коде: https://github.com/SagerNet/sing-box/releases/tag/v1.12.25
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from typing import List, Optional, Tuple

# Хардкод релиза (как просили)
SINGBOX_RELEASE_TAG = "v1.12.25"
SINGBOX_VERSION = "1.12.25"
DOWNLOAD_BASE = (
    f"https://github.com/SagerNet/sing-box/releases/download/{SINGBOX_RELEASE_TAG}/"
)

USER_AGENT = "antivpn-probe-singbox-fetch/1.0"


def _is_termux() -> bool:
    prefix = os.environ.get("PREFIX", "")
    return "com.termux" in prefix


def _machine() -> str:
    return platform.machine().lower()


def resolve_asset_filename() -> Tuple[str, str]:
    """
    Имя файла на GitHub и тип архива: 'zip' | 'tgz'.
    См. ассеты релиза: https://github.com/SagerNet/sing-box/releases/tag/v1.12.25
    """
    if sys.platform == "win32":
        m = _machine()
        if m in ("amd64", "x86_64"):
            suf = "windows-amd64"
        elif m in ("arm64", "aarch64"):
            suf = "windows-arm64"
        else:
            suf = "windows-386"
        return f"sing-box-{SINGBOX_VERSION}-{suf}.zip", "zip"

    if _is_termux():
        m = _machine()
        if m in ("aarch64", "arm64"):
            suf = "android-arm64"
        elif m.startswith("arm"):
            suf = "android-arm"
        elif m in ("x86_64", "amd64"):
            suf = "android-amd64"
        elif m in ("i386", "i686", "x86"):
            suf = "android-386"
        else:
            suf = "android-arm64"
        return f"sing-box-{SINGBOX_VERSION}-{suf}.tar.gz", "tgz"

    m = _machine()
    if m in ("x86_64", "amd64"):
        suf = "linux-amd64"
    elif m in ("aarch64", "arm64"):
        suf = "linux-arm64"
    elif m.startswith("armv7") or m in ("armv6l", "armhf"):
        suf = "linux-armv7"
    elif m in ("i386", "i686", "x86"):
        suf = "linux-386"
    elif m.startswith("arm"):
        suf = "linux-armv7"
    else:
        suf = "linux-amd64"
    return f"sing-box-{SINGBOX_VERSION}-{suf}.tar.gz", "tgz"


def _basename_match(name: str, want: str) -> bool:
    base = name.replace("\\", "/").rstrip("/").split("/")[-1].lower()
    return base == want.lower()


def _find_member(names: List[str], want: str) -> Optional[str]:
    for n in names:
        if _basename_match(n, want):
            return n
    return None


def _download(url: str, dest: str, timeout: float = 120.0) -> None:
    try:
        import requests as _req
        r = _req.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT},
                     allow_redirects=True, stream=True)
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
        return
    except ImportError:
        pass
    except Exception:
        pass
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        with open(dest, "wb") as f:
            shutil.copyfileobj(resp, f)


def _extract_zip_member(z: zipfile.ZipFile, member: str, dest_dir: str) -> str:
    info = z.getinfo(member)
    if info.is_dir():
        raise ValueError("member is dir")
    base = os.path.basename(member.replace("\\", "/"))
    out = os.path.join(dest_dir, base)
    with z.open(info, "r") as src, open(out, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return out


def _extract_tar_member(
    tar: tarfile.TarFile, member: str, dest_dir: str,
) -> str:
    m = tar.getmember(member)
    if not m.isfile():
        raise ValueError("not a file")
    f = tar.extractfile(m)
    if not f:
        raise ValueError("extractfile failed")
    base = os.path.basename(member.rstrip("/"))
    out = os.path.join(dest_dir, base)
    with open(out, "wb") as dst:
        shutil.copyfileobj(f, dst)
    return out


def ensure_singbox(script_dir: str, quiet: bool = False) -> Optional[str]:
    """
    Кладёт sing-box в script_dir/bin/ при отсутствии в PATH и рядом со скриптом.
    Возвращает путь к исполняемому файлу или None.
    """
    is_win = sys.platform == "win32"
    exe_name = "sing-box.exe" if is_win else "sing-box"
    bin_dir = os.path.join(script_dir, "bin")
    target = os.path.join(bin_dir, exe_name)

    if os.path.isfile(target):
        return target

    try:
        asset, kind = resolve_asset_filename()
    except Exception:
        return None

    url = DOWNLOAD_BASE + asset
    if not quiet:
        print(f"  sing-box: скачивание {asset} …", flush=True)

    tmp_dir_base = None
    if _is_termux():
        prefix = os.environ.get("PREFIX", "")
        termux_tmp = os.path.join(prefix, "tmp")
        if os.path.isdir(termux_tmp) and os.access(termux_tmp, os.W_OK):
            tmp_dir_base = termux_tmp
    tmp = tempfile.mkdtemp(prefix="singbox-dl-", dir=tmp_dir_base)
    try:
        archive_path = os.path.join(tmp, asset)
        try:
            _download(url, archive_path)
        except Exception as e:
            if not quiet:
                print(f"  sing-box: ошибка загрузки: {e}", flush=True)
            return None

        os.makedirs(bin_dir, exist_ok=True)

        binary_path: Optional[str] = None
        if kind == "zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                names = zf.namelist()
                mem = _find_member(names, exe_name)
                if not mem:
                    if not quiet:
                        print("  sing-box: в zip нет sing-box.exe", flush=True)
                    return None
                binary_path = _extract_zip_member(zf, mem, bin_dir)
        else:
            with tarfile.open(archive_path, "r:gz") as tf:
                names = [m.name for m in tf.getmembers() if m.isfile()]
                mem = _find_member(names, exe_name)
                if not mem:
                    if not quiet:
                        print("  sing-box: в архиве нет sing-box", flush=True)
                    return None
                binary_path = _extract_tar_member(tf, mem, bin_dir)

        if not binary_path or not os.path.isfile(binary_path):
            return None
        if not is_win:
            try:
                os.chmod(binary_path, 0o755)
            except OSError:
                pass
            if not os.access(binary_path, os.X_OK):
                if not quiet:
                    print(
                        f"  sing-box: скачан, но нет прав на запуск.\n"
                        f"  Выполните вручную: chmod +x \"{binary_path}\"",
                        flush=True,
                    )
        return binary_path
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
