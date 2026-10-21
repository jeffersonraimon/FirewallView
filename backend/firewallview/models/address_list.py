from typing import List, Optional
from pydantic import BaseModel, Field

class AddressListEntry(BaseModel):
    id: Optional[str] = None
    address: str # IP ex: 10.0.0.1, CIDR ex: 192.168.0.0/24, or Range ex: 10.0.0.1-10.0.0.50
    comment: Optional[str] = None
    disabled: bool = False

class AddressList(BaseModel):
    name: str
    entries: List[AddressListEntry] = Field(default_factory=list)
