from dataclasses import dataclass, field
from typing import List


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str
    product: str = ""
    version: str = ""
    cpe: str = ""
    reason: str = ""
    extra_info: str = ""


@dataclass
class Asset:
    host: str
    status: str
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    os_name: str = ""
    os_family: str = ""
    os_generation: str = ""
    os_accuracy: str = ""
    uptime_seconds: int = 0
    ports: List[Port] = field(default_factory=list)

    def add_port(self, port: Port):
        self.ports.append(port)

    @property
    def open_ports(self):
        return [port for port in self.ports if port.state == "open"]
