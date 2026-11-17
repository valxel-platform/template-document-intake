"""What a file is, by its content; and whether it carries malware.

A file's name and the Content-Type the browser sent are never trusted: the format is read from the
file's first bytes, and must be one its document type allows and the one the uploader declared.

The scanner is the platform's ClamAV (clamd's INSTREAM command over TCP). A scan that can't run
is an error, never a pass: the document waits and is scanned again.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

MIME = {"pdf": "application/pdf", "png": "image/png", "jpeg": "image/jpeg", "tiff": "image/tiff"}


def sniff(head: bytes) -> str | None:
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    return None


@dataclass(frozen=True)
class Verdict:
    clean: bool
    threat: str = ""  # the signature's name when infected


class ScanError(RuntimeError):
    """The scanner couldn't give a verdict: try again later; never treat as clean."""


class ClamdScanner:
    CHUNK = 65536

    def __init__(self, host: str, port: int, timeout_s: float = 60.0) -> None:
        self.host, self.port, self.timeout_s = host, port, timeout_s

    def scan(self, data: bytes) -> Verdict:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout_s) as s:
                s.sendall(b"zINSTREAM\0")
                for i in range(0, len(data), self.CHUNK):
                    chunk = data[i : i + self.CHUNK]
                    s.sendall(struct.pack(">I", len(chunk)) + chunk)
                s.sendall(struct.pack(">I", 0))
                reply = b""
                while not reply.endswith(b"\0"):
                    part = s.recv(4096)
                    if not part:
                        break
                    reply += part
        except OSError as exc:
            raise ScanError(f"the malware scanner can't be reached ({type(exc).__name__})") from exc
        return parse_reply(reply.rstrip(b"\0").decode("utf-8", errors="replace"))


def parse_reply(text: str) -> Verdict:
    # "stream: OK" | "stream: Eicar-Signature FOUND" | "INSTREAM size limit exceeded. ERROR"
    if text.endswith(" OK"):
        return Verdict(True)
    if text.endswith(" FOUND"):
        return Verdict(False, text.split(": ", 1)[-1].removesuffix(" FOUND").strip()[:100])
    raise ScanError("the malware scanner answered with an error")


class NoScanner:
    """Local development only: refused in staging and production (app.build)."""

    EICAR = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    def scan(self, data: bytes) -> Verdict:
        return Verdict(False, "Eicar-Test-Signature") if self.EICAR in data else Verdict(True)
