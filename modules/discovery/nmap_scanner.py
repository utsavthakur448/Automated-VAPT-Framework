import nmap

class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan(self, target):
        return self.scanner.scan(hosts=target, arguments="-sV -O -R")
