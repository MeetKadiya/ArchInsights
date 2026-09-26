import asyncio
import logging
from typing import List, Dict, Any

from app.domain_scanner.models import PortServiceInfo

logger = logging.getLogger(__name__)

TARGET_PORTS: List[Dict[str, Any]] = [
    {"port": 80, "service": "HTTP", "category": "web", "sensitive": False},
    {"port": 443, "service": "HTTPS", "category": "web", "sensitive": False},
    {"port": 8080, "service": "HTTP-Proxy / Alt", "category": "web", "sensitive": False},
    {"port": 8443, "service": "HTTPS-Alt", "category": "web", "sensitive": False},
    {"port": 8000, "service": "HTTP-Dev (uvicorn/django)", "category": "web", "sensitive": False},
    {"port": 3000, "service": "Node.js / React Dev Server", "category": "web", "sensitive": False},
    {"port": 5000, "service": "Flask / Express Service", "category": "web", "sensitive": False},
    {"port": 22, "service": "SSH", "category": "remote_access", "sensitive": False},
    {"port": 21, "service": "FTP (Plaintext)", "category": "remote_access", "sensitive": True},
    {"port": 25, "service": "SMTP Mail", "category": "messaging", "sensitive": False},
    {"port": 53, "service": "DNS", "category": "infrastructure", "sensitive": False},
    {"port": 3306, "service": "MySQL Database", "category": "database", "sensitive": True},
    {"port": 5432, "service": "PostgreSQL Database", "category": "database", "sensitive": True},
    {"port": 6379, "service": "Redis Cache / Store", "category": "database", "sensitive": True},
    {"port": 27017, "service": "MongoDB Database", "category": "database", "sensitive": True},
    {"port": 9200, "service": "Elasticsearch REST API", "category": "database", "sensitive": True},
]


class PortScannerEngine:
    """
    High-speed asynchronous TCP port scanner targeting standard web,
    cloud infrastructure, and exposed database/cache services.
    """

    def __init__(self, timeout: float = 0.85, concurrency: int = 16):
        self.timeout = timeout
        self.concurrency = concurrency

    async def scan(self, domain: str) -> List[PortServiceInfo]:
        """
        Scans target domain against defined ports and returns list of open ports.
        """
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check_port(port_def: Dict[str, Any]) -> PortServiceInfo:
            async with semaphore:
                port = port_def["port"]
                service = port_def["service"]
                category = port_def["category"]
                is_sensitive = port_def["sensitive"]

                is_open = False
                banner = None

                try:
                    conn = asyncio.open_connection(domain, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                    is_open = True

                    # Try a lightweight banner grab
                    try:
                        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                        await asyncio.wait_for(writer.drain(), timeout=0.3)
                        line = await asyncio.wait_for(reader.readline(), timeout=0.4)
                        if line:
                            banner = line.decode("utf-8", errors="ignore").strip()[:80]
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass

                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    is_open = False

                return PortServiceInfo(
                    port=port,
                    service_name=service,
                    protocol="tcp",
                    is_open=is_open,
                    banner=banner,
                    category=category,
                    is_sensitive=is_sensitive,
                )

        tasks = [check_port(p) for p in TARGET_PORTS]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r.is_open]
