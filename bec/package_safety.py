"""Local-path, bounded-read and exclusive-publication guards for evidence packages."""
import ctypes
import os
import re
import stat
import sys
from pathlib import Path

from .bundles import local_path
from .comparison import MAX_CASE_BYTES, MAX_FILE_BYTES, Snapshot
from .storage import CaseError, digest


def safe_name(value):
    stem = value.split(".", 1)[0].rstrip(" .").upper()
    if (not value or value in {".", ".."} or value.endswith((" ", ".")) or len(value) > 180 or
            re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', value) or
            stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"} or
            re.fullmatch(r"(?:COM|LPT)[1-9\u00b9\u00b2\u00b3]", stem)):
        raise CaseError("Package paths require safe local Windows-compatible names.")
    return value


def safe_path(value, *, exists=False, directory=False):
    path = local_path(value)
    for part in path.parts:
        if part != path.anchor:
            safe_name(part)
    for current in (*reversed(path.parents), path):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise CaseError("Package inputs and outputs cannot use symbolic links or reparse points.")
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise CaseError("Package path ancestor is not a directory.")
    if exists:
        if not path.exists() or (directory and not path.is_dir()) or (not directory and not path.is_file()):
            raise CaseError("Package input is missing or has the wrong file type.")
    return path


def inspect_tree(directory):
    directory = safe_path(directory, exists=True, directory=True)
    count = 0
    for parent, dirs, files in os.walk(directory, followlinks=False):
        for name in (*dirs, *files):
            count += 1
            if count > 20000:
                raise CaseError("Package input has too many filesystem entries.")
            item = safe_path(Path(parent) / name, exists=True, directory=name in dirs)
            mode = item.lstat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise CaseError("Package input contains a non-regular filesystem entry.")
    return directory


def read_bytes(path, limit=MAX_FILE_BYTES):
    path = safe_path(path, exists=True)
    expected = path.stat()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_size > limit or
                (before.st_dev, before.st_ino) != (expected.st_dev, expected.st_ino)):
            raise CaseError("Package source is not a bounded regular file.")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    safe_path(path, exists=True)
    current = path.stat()

    def file_state(info):
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

    # Windows Python can report creation time for stat(path) and change time for
    # fstat(fd). Compare ctime within each API and file identity across both.
    if (len(raw) != before.st_size or len(raw) > limit or
            not file_state(expected) == file_state(before) == file_state(after) == file_state(current) or
            expected.st_ctime_ns != current.st_ctime_ns or before.st_ctime_ns != after.st_ctime_ns):
        raise CaseError("Package source changed during its bounded read.")
    return raw


class PackageSnapshot(Snapshot):
    """Reuse read-only case verification with stricter local file admission."""
    def __init__(self, directory):
        directory = inspect_tree(directory)
        self.file_states = {}
        self.total_bytes = 0
        super().__init__(directory)

    def watch(self, path, optional=False):
        path = safe_path(path)
        if optional and not path.exists():
            data, state = None, None
        else:
            data = read_bytes(path)
            info = path.stat()
            state = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            self.total_bytes += len(data)
            if self.total_bytes > MAX_CASE_BYTES:
                raise CaseError("Package source case exceeds 512 MiB.")
        self.watched[path] = digest(data) if data is not None else None
        self.file_states[path] = state
        return data

    def check_unchanged(self):
        inspect_tree(self.case.path)
        if (self.case.path / ".pending-artifact.json").exists():
            raise CaseError("Case acquisition is pending; package it after collection finishes.")
        for path, expected in self.watched.items():
            if path.exists():
                info = path.stat()
                state = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                actual = digest(read_bytes(path))
            else:
                state, actual = None, None
            if expected != actual or self.file_states[path] != state:
                raise CaseError("Source case changed while building its package.")
        self.check_inventory()


def publish_directory(source, target):
    """Atomically rename a staged directory, refusing an existing destination."""
    source, target = safe_path(source, exists=True, directory=True), safe_path(target)
    if target.exists():
        raise CaseError("A package acquisition directory already exists.")
    if os.name == "nt":
        os.rename(source, target)  # Windows rename refuses an existing destination.
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        function = libc.renamex_np
        function.argtypes, function.restype = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint], ctypes.c_int
        result = function(os.fsencode(source), os.fsencode(target), 0x00000004)  # RENAME_EXCL, sys/stdio.h.
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes, function.restype = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint], ctypes.c_int
        result = function(-100, os.fsencode(source), -100, os.fsencode(target), 1)  # AT_FDCWD, RENAME_NOREPLACE.
    else:
        raise CaseError("This platform lacks a supported atomic no-overwrite directory rename.")
    if result:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(target))
