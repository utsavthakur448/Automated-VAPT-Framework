from dataclasses import dataclass, field
from typing import List

from core.asset import Asset


@dataclass
class ScanResult:
    target: str
    assets: List[Asset] = field(default_factory=list)

    def add_asset(self, asset: Asset):
        self.assets.append(asset)

    @property
    def total_hosts(self):
        return len(self.assets)

    @property
    def total_open_ports(self):
        return sum(len(asset.open_ports) for asset in self.assets)
