"""
IPinfo API集成
"""

from typing import Any, Dict, cast

from src.config import ApiEndpointConfig
from src.modules.threat_intel.base_api import BaseApi


class IPinfoApi(BaseApi):
    """IPinfo API集成"""
    
    def __init__(self, api_key: str, config: ApiEndpointConfig):
        """
        初始化IPinfo API
        
        Args:
            api_key: API密钥
            config: API配置
        """
        super().__init__("ipinfo", api_key, config)
    
    def _add_auth(self, headers: Dict[str, str]) -> bool:
        """
        添加认证信息到请求头
        
        Args:
            headers: 请求头字典
            
        Returns:
            bool: 是否成功添加认证信息
        """
        if not self.api_key:
            return False
        
        headers["Authorization"] = f"Bearer {self.api_key}"
        return True
    
    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP信息
        
        Args:
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        endpoint = f"/{ip}"
        
        success, response, status_code = await self._request("GET", endpoint)
        
        if not success:
            return self._process_error_response(str(response), status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_ip_response(cast(Dict[str, Any], response))
        }
        
        return result
    
    async def query_url(self, url: str) -> Dict[str, Any]:
        """
        查询URL信息（IPinfo不支持URL查询）
        
        Args:
            url: URL
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": "IPinfo不支持URL查询",
            "status_code": 0,
            "data": None
        }
    
    async def query_hash(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """
        查询文件哈希信息（IPinfo不支持哈希查询）
        
        Args:
            hash_value: 哈希值
            hash_type: 哈希类型
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": "IPinfo不支持文件哈希查询",
            "status_code": 0,
            "data": None
        }
    
    def _normalize_ip_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        标准化IP响应数据
        
        Args:
            response: API响应
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        if not response:
            return {"raw": response}
        
        # 提取地理位置信息
        ip = response.get("ip", "")
        hostname = response.get("hostname", "")
        city = response.get("city", "")
        region = response.get("region", "")
        country = response.get("country", "")
        country_name = response.get("country_name", "")
        loc = response.get("loc", "")
        postal = response.get("postal", "")
        timezone = response.get("timezone", "")
        
        # 提取网络信息
        org = response.get("org", "")
        asn = ""
        as_name = ""
        
        # 解析ASN和AS名称（通常格式为"ASXXXXX 组织名称"）
        if org:
            parts = org.split(" ", 1)
            if len(parts) > 0 and parts[0].startswith("AS"):
                asn = parts[0].replace("AS", "")
                if len(parts) > 1:
                    as_name = parts[1]
        
        # 解析经纬度
        latitude = None
        longitude = None
        if loc:
            try:
                lat_lon = loc.split(",")
                if len(lat_lon) >= 2:
                    latitude = float(lat_lon[0])
                    longitude = float(lat_lon[1])
            except (ValueError, IndexError):
                pass
        
        # 标准化数据
        normalized = {
            "ip": ip,
            "hostname": hostname,
            "city": city,
            "region": region,
            "country": country,
            "country_name": country_name,
            "postal": postal,
            "timezone": timezone,
            "asn": asn,
            "as_name": as_name,
            "org": org,
            "coordinates": {
                "latitude": latitude,
                "longitude": longitude
            } if latitude is not None and longitude is not None else {},
            "privacy": {
                "is_tor": False,  # IPinfo基础API不提供这些信息
                "is_proxy": False,
                "is_vpn": False
            },
            "threat_score": 0.0,  # IPinfo基础API不提供威胁评分
            "raw": response
        }
        
        # 如果有abuse属性，提取滥用联系信息
        if "abuse" in response:
            abuse = response["abuse"]
            normalized["abuse"] = {
                "address": abuse.get("address", ""),
                "country": abuse.get("country", ""),
                "email": abuse.get("email", ""),
                "name": abuse.get("name", ""),
                "network": abuse.get("network", ""),
                "phone": abuse.get("phone", "")
            }
        
        # 如果有privacy属性，更新隐私信息
        if "privacy" in response:
            privacy = response["privacy"]
            normalized["privacy"] = {
                "is_tor": privacy.get("tor", False),
                "is_proxy": privacy.get("proxy", False),
                "is_vpn": privacy.get("vpn", False),
                "is_hosting": privacy.get("hosting", False),
                "is_service": privacy.get("service", False)
            }
            
            # 基于隐私信息计算威胁分数
            threat_score = 0.0
            if privacy.get("tor", False):
                threat_score += 0.3
            if privacy.get("proxy", False):
                threat_score += 0.2
            if privacy.get("vpn", False):
                threat_score += 0.1
                
            normalized["threat_score"] = min(threat_score, 1.0)
        
        return normalized 