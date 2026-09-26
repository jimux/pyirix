"""Minimal pure-Python NBD client + a qemu-nbd-backed file object.

This is the read/write path behind :func:`pyirix.xfs.image.open_disk_image` for
qcow2 images. Why NBD instead of a raw `qemu-img convert` round-trip:

* no temporary copy of the disk (the old path materialised the whole image into
  a temp file, which on these nodes is a RAM tmpfs `/tmp`);
* writes go through QEMU's block layer in place with `--cache=writethrough`, so
  there is no destructive flattened write-back and an overlay stays an overlay
  (top-layer writes, backing untouched);
* QEMU's image locking comes for free: `qemu-nbd` refuses an image a running VM
  already holds.

The client speaks fixed-newstyle NBD (option haggling) over a unix socket.
libnbd is not required (and is not installed here).
"""

import os
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Optional

from pyirix.tmpdir import tmp_dir

# Handshake magic
NBDMAGIC = 0x4E42444D41474943
IHAVEOPT = 0x49484156454F5054
NBD_REP_MAGIC = 0x0003E889045565A9

# Handshake flags
NBD_FLAG_FIXED_NEWSTYLE = 1 << 0
NBD_FLAG_NO_ZEROES = 1 << 1

# Client flags
NBD_FLAG_C_FIXED_NEWSTYLE = 1 << 0
NBD_FLAG_C_NO_ZEROES = 1 << 1

# Options
NBD_OPT_GO = 7

# Option reply types
NBD_REP_ACK = 1
NBD_REP_INFO = 3
NBD_REP_ERR_UNSUP = 0x80000001

# Info types
NBD_INFO_EXPORT = 0
NBD_INFO_BLOCK_SIZE = 3

# Transmission magic
NBD_REQUEST_MAGIC = 0x25609513
NBD_REPLY_MAGIC = 0x67446698

# Commands
NBD_CMD_READ = 0
NBD_CMD_WRITE = 1
NBD_CMD_DISC = 2
NBD_CMD_FLUSH = 3

# NBD hard limit is 32 MiB per request; stay under it.
_MAX_CHUNK = 16 * 1024 * 1024


class NbdError(OSError):
    """An NBD protocol or command error."""


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise NbdError("NBD connection closed unexpectedly")
        buf += chunk
    return bytes(buf)


def _read_u32(sock):
    return struct.unpack(">I", _recv_exact(sock, 4))[0]


def _read_u64(sock):
    return struct.unpack(">Q", _recv_exact(sock, 8))[0]


class NbdFile:
    """A seekable file-like object over an NBD export."""

    def __init__(self, sock, size: int, readonly: bool):
        self._sock = sock
        self._size = size
        self._pos = 0
        self._handle = 0
        self.readonly = readonly
        self.closed = False

    # -- helpers -----------------------------------------------------------
    def _next_handle(self) -> int:
        self._handle += 1
        return self._handle

    def _flush_reply(self, handle):
        magic = _read_u32(self._sock)
        if magic != NBD_REPLY_MAGIC:
            raise NbdError(f"bad NBD reply magic 0x{magic:08x}")
        error = _read_u32(self._sock)
        got = _read_u64(self._sock)
        if got != handle:
            raise NbdError("NBD reply handle mismatch")
        if error != 0:
            raise NbdError(f"NBD command failed with error {error}")

    def _request(self, cmd, offset, length=0, data=b""):
        handle = self._next_handle()
        self._sock.sendall(struct.pack(
            ">IHHQQI", NBD_REQUEST_MAGIC, 0, cmd, handle, offset, length))
        if data:
            self._sock.sendall(data)
        return handle

    # -- file API ----------------------------------------------------------
    def seek(self, offset, whence=0):
        if whence == 0:
            pos = offset
        elif whence == 1:
            pos = self._pos + offset
        elif whence == 2:
            pos = self._size + offset
        else:
            raise ValueError("invalid whence")
        self._pos = max(0, pos)
        return self._pos

    def tell(self):
        return self._pos

    def size(self):
        return self._size

    def readable(self):
        return True

    def writable(self):
        return not self.readonly

    def seekable(self):
        return True

    def read(self, n=-1):
        if n is None or n < 0:
            n = max(0, self._size - self._pos)
        n = min(n, max(0, self._size - self._pos))
        out = bytearray()
        while len(out) < n:
            want = min(_MAX_CHUNK, n - len(out))
            handle = self._request(NBD_CMD_READ, self._pos + len(out), want)
            magic = _read_u32(self._sock)
            if magic != NBD_REPLY_MAGIC:
                raise NbdError(f"bad NBD read reply magic 0x{magic:08x}")
            error = _read_u32(self._sock)
            got = _read_u64(self._sock)
            if got != handle:
                raise NbdError("NBD read reply handle mismatch")
            if error != 0:
                raise NbdError(f"NBD read failed with error {error}")
            out += _recv_exact(self._sock, want)
        self._pos += len(out)
        return bytes(out)

    def readinto(self, b):
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)

    def write(self, data):
        if self.readonly:
            raise NbdError("NBD export is read-only")
        mv = memoryview(data)
        total = 0
        while total < len(mv):
            chunk = mv[total:total + _MAX_CHUNK]
            handle = self._request(NBD_CMD_WRITE, self._pos, len(chunk), chunk.tobytes())
            self._flush_reply(handle)
            self._pos += len(chunk)
            total += len(chunk)
        return len(mv)

    def flush(self):
        if self.closed:
            return
        handle = self._request(NBD_CMD_FLUSH, 0)
        self._flush_reply(handle)

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self._sock.sendall(struct.pack(
                ">IHHQQI", NBD_REQUEST_MAGIC, 0, NBD_CMD_DISC, 0, 0, 0))
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _handshake(path: str, readonly: bool = False, timeout: float = 10.0) -> NbdFile:
    """Connect to a qemu-nbd unix socket and negotiate an export."""
    deadline = time.time() + timeout
    sock = None
    last = None
    while time.time() < deadline:
        if os.path.exists(path):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(path)
            except OSError as exc:
                last = exc
                s.close()
                time.sleep(0.05)
                continue
            sock = s
            break
        time.sleep(0.05)
    if sock is None:
        raise NbdError(f"could not connect to qemu-nbd socket {path}: {last}")

    try:
        magic = _read_u64(sock)
        opt_magic = _read_u64(sock)
        flags = struct.unpack(">H", _recv_exact(sock, 2))[0]
        if magic != NBDMAGIC or opt_magic != IHAVEOPT:
            raise NbdError("not an NBD fixed-newstyle server")
        client_flags = NBD_FLAG_C_FIXED_NEWSTYLE
        if flags & NBD_FLAG_NO_ZEROES:
            client_flags |= NBD_FLAG_C_NO_ZEROES
        sock.sendall(struct.pack(">I", client_flags))

        # NBD_OPT_GO with an empty export name and no info requests.
        go_data = struct.pack(">I", 0) + struct.pack(">H", 0)
        sock.sendall(struct.pack(">QII", IHAVEOPT, NBD_OPT_GO, len(go_data)) + go_data)
        size = None
        while True:
            rep_magic = _read_u64(sock)
            if rep_magic != NBD_REP_MAGIC:
                raise NbdError("bad NBD option reply magic")
            option = _read_u32(sock)
            rep_type = _read_u32(sock)
            length = _read_u32(sock)
            data = _recv_exact(sock, length) if length else b""
            if rep_type == NBD_REP_ACK:
                break
            if rep_type == NBD_REP_INFO and len(data) >= 2:
                info_type = struct.unpack(">H", data[:2])[0]
                if info_type == NBD_INFO_EXPORT and len(data) >= 10:
                    size = struct.unpack(">Q", data[2:10])[0]
            elif rep_type == NBD_REP_ERR_UNSUP:
                raise NbdError("server does not support NBD_OPT_GO")
            elif rep_type & 0x80000000:
                raise NbdError(f"NBD option negotiation error 0x{rep_type:08x}")
        if size is None:
            raise NbdError("server did not report export size")
        return NbdFile(sock, size, readonly=readonly)
    except BaseException:
        if sock is not None:
            sock.close()
        raise


class QemuNbd:
    """Context manager running `qemu-nbd` on a unix socket for one image.

    Yields a file-like object over the export. Always sends NBD_CMD_DISC and
    reaps the exact Popen it spawned (never by process-name pattern).
    """

    def __init__(self, image, readonly=False, cache="writethrough",
                 qemu_nbd="qemu-nbd"):
        self.image = str(image)
        self.readonly = readonly
        self.cache = cache
        self.qemu_nbd = qemu_nbd
        self._proc = None
        self._sockdir = None
        self._sockfile = None
        self._file = None
        self._last_stderr = ""

    def __enter__(self):
        self._sockdir = tmp_dir(prefix="nbd_")
        self._sockfile = os.path.join(self._sockdir, "sock")
        args = [self.qemu_nbd, "-k", self._sockfile, "-f", "qcow2",
                "--cache", self.cache]
        if self.readonly:
            args.append("-r")
        args.append(self.image)
        self._proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            f = _handshake(self._sockfile, readonly=self.readonly)
        except BaseException as exc:
            self._cleanup()
            if self._last_stderr:
                raise NbdError(
                    f"qemu-nbd failed for {self.image}: {self._last_stderr}") from exc
            raise
        self._file = f
        return f

    def _cleanup(self):
        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            # Surface an early-exit message (e.g. image locking refusal).
            err = b""
            try:
                if self._proc.stderr is not None:
                    err = self._proc.stderr.read() or b""
            except OSError:
                pass
            self._proc = None
            if err and err.strip():
                self._last_stderr = err.decode("utf-8", "replace").strip()
        if self._sockfile:
            try:
                os.unlink(self._sockfile)
            except OSError:
                pass
        if self._sockdir:
            try:
                os.rmdir(self._sockdir)
            except OSError:
                pass

    def __exit__(self, *exc):
        self._file = getattr(self, "_file", None)
        self._cleanup()
        return False


def open_nbd(image, readonly=False, qemu_nbd="qemu-nbd"):
    """Return an NbdFile for *image* (caller must close it)."""
    mgr = QemuNbd(image, readonly=readonly, qemu_nbd=qemu_nbd)
    return mgr.__enter__(), mgr
