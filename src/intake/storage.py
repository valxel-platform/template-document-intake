"""Where files are: a quarantine bucket uploads land in, and a clean bucket for checked files.

Uploads go straight from the browser to quarantine through a presigned POST that holds only for a
few minutes, one key, the declared Content-Type and at most the type's size. Nothing reads from
quarantine but the pipeline. A file moves to the clean bucket (encrypted with the product's KMS
key) only after its checks pass; downloads are presigned GETs that last a minute and name the file.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Protocol


class Missing(LookupError):
    pass


@dataclass(frozen=True)
class Upload:
    url: str
    fields: dict[str, str]


class Storage(Protocol):
    def presign_upload(self, key: str, content_type: str, max_bytes: int, ttl_s: int) -> Upload: ...
    def read_quarantine(self, key: str, limit: int) -> bytes: ...
    def promote(self, key: str, data: bytes, content_type: str) -> None: ...
    def drop_quarantine(self, key: str) -> None: ...
    def presign_download(self, key: str, filename: str, ttl_s: int) -> str: ...
    def delete_clean(self, key: str) -> None: ...


class MemoryStorage:
    def __init__(self) -> None:
        self.quarantine: dict[str, bytes] = {}
        self.clean: dict[str, tuple[bytes, str]] = {}
        self.lock = threading.Lock()

    def presign_upload(self, key: str, content_type: str, max_bytes: int, ttl_s: int) -> Upload:
        return Upload(
            url="memory://quarantine",
            fields={
                "key": key,
                "Content-Type": content_type,
                "x-max-bytes": str(max_bytes),
                "x-ttl": str(ttl_s),
            },
        )

    def put_quarantine(self, key: str, data: bytes) -> None:  # what the browser's POST does
        self.quarantine[key] = data

    def read_quarantine(self, key: str, limit: int) -> bytes:
        if key not in self.quarantine:
            raise Missing(key)
        return self.quarantine[key][: limit + 1]

    def promote(self, key: str, data: bytes, content_type: str) -> None:
        with self.lock:
            self.clean[key] = (data, content_type)

    def drop_quarantine(self, key: str) -> None:
        self.quarantine.pop(key, None)

    def presign_download(self, key: str, filename: str, ttl_s: int) -> str:
        if key not in self.clean:
            raise Missing(key)
        return f"memory://clean/{key}?ttl={ttl_s}"

    def delete_clean(self, key: str) -> None:
        self.clean.pop(key, None)


class S3Storage:
    def __init__(self, *, quarantine: str, clean: str, kms_key_id: str, client: Any = None) -> None:
        if not (quarantine and clean and kms_key_id):
            raise RuntimeError(
                "s3 storage needs INTAKE_QUARANTINE_BUCKET, INTAKE_CLEAN_BUCKET and INTAKE_KMS_KEY_ID"
            )
        if quarantine == clean:
            raise RuntimeError("the quarantine and clean buckets must differ")
        if client is None:
            import boto3

            client = boto3.client("s3")
        self.s3, self.quarantine, self.clean, self.kms = client, quarantine, clean, kms_key_id

    def presign_upload(self, key: str, content_type: str, max_bytes: int, ttl_s: int) -> Upload:
        post = self.s3.generate_presigned_post(
            Bucket=self.quarantine,
            Key=key,
            Fields={"Content-Type": content_type},
            Conditions=[{"Content-Type": content_type}, ["content-length-range", 1, max_bytes]],
            ExpiresIn=ttl_s,
        )
        return Upload(url=post["url"], fields={k: str(v) for k, v in post["fields"].items()})

    def read_quarantine(self, key: str, limit: int) -> bytes:
        try:
            obj = self.s3.get_object(Bucket=self.quarantine, Key=key, Range=f"bytes=0-{limit}")
        except self.s3.exceptions.NoSuchKey as exc:
            raise Missing(key) from exc
        data: bytes = obj["Body"].read()
        return data

    def promote(self, key: str, data: bytes, content_type: str) -> None:
        self.s3.put_object(
            Bucket=self.clean,
            Key=key,
            Body=data,
            ContentType=content_type,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self.kms,
        )

    def drop_quarantine(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.quarantine, Key=key)

    def presign_download(self, key: str, filename: str, ttl_s: int) -> str:
        url: str = self.s3.generate_presigned_url(
            "get_object",
            ExpiresIn=ttl_s,
            Params={
                "Bucket": self.clean,
                "Key": key,
                "ResponseContentDisposition": f'attachment; filename="{filename}"',
            },
        )
        return url

    def delete_clean(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.clean, Key=key)
