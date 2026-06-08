"""Geo and ASN enrichment via ip-api with MaxMind fallback."""

import aiohttp
import logging

logger = logging.getLogger(__name__)


class GeoASNClient:
    IP_API = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,isp,org,as,query"

    def __init__(self, maxmind_path: str = ""):
        self.maxmind_path = maxmind_path
        self._reader = None
        if maxmind_path:
            try:
                import geoip2.database

                self._reader = geoip2.database.Reader(maxmind_path)
            except Exception as exc:
                logger.warning("MaxMind DB not loaded: %s", exc)

    async def lookup_ip(self, ip: str) -> dict:
        if self._reader:
            return self._lookup_maxmind(ip)
        return await self._lookup_ip_api(ip)

    async def _lookup_ip_api(self, ip: str) -> dict:
        url = self.IP_API.format(ip=ip)
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                if data.get("status") != "success":
                    return {}
                return {
                    "country": data.get("country"),
                    "countryCode": data.get("countryCode"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                }

    def _lookup_maxmind(self, ip: str) -> dict:
        try:
            response = self._reader.city(ip)
            return {
                "country": response.country.name,
                "countryCode": response.country.iso_code,
                "city": response.city.name,
                "lat": response.location.latitude,
                "lon": response.location.longitude,
            }
        except Exception:
            return {}
