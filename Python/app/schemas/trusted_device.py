# auth_api/app/schemas/trusted_device.py
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class TrustedDeviceInfo(BaseModel):
    """Informações sobre um dispositivo confiável registrado."""
    id: int
    description: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    last_used_at: Optional[datetime]

    class Config:
        from_attributes = True