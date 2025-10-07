from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

@dataclass
class TenantCreateDTO:
    name: str
    slug: Optional[str] = None
    active: bool = True

@dataclass
class UserCreateDTO:
    email: str
    full_name: Optional[str] = None
    password: Optional[str] = None
    tenant_id: int = 0
    active: bool = True
