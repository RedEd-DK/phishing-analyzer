import os
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID


@dataclass(frozen=True)
class Config:
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)
    mailbox: str = "phishing@rededucation.com"
    poll_seconds: int = 60
    data_dir: Path = Path("data")
    max_message_bytes: int = 25 * 1024 * 1024

    @classmethod
    def from_env(cls):
        tenant = os.environ.get("TENANT_ID", "9070ef23-9a31-45a8-9b14-45111a4ebbbe")
        client = os.environ.get("CLIENT_ID", "3e16daef-f2ac-4761-86eb-2d80e04d9a7a")
        UUID(tenant)
        UUID(client)
        secret = os.environ.get("CLIENT_SECRET", "").strip()
        if not secret or secret == "replace-me":
            raise ValueError("Set CLIENT_SECRET in your local environment or Compose .env file")
        interval = int(os.environ.get("POLL_SECONDS", "60"))
        limit = int(os.environ.get("MAX_MESSAGE_BYTES", str(25 * 1024 * 1024)))
        mailbox = os.environ.get("MAILBOX", "phishing@rededucation.com").strip()
        if interval < 5 or limit < 1024 or "@" not in mailbox:
            raise ValueError("Require POLL_SECONDS >= 5, MAX_MESSAGE_BYTES >= 1024 and a mailbox address")
        return cls(tenant, client, secret, mailbox, interval,
                   Path(os.environ.get("DATA_DIR", "data")), limit)
