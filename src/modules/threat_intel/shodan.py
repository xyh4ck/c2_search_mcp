"""
Shodan API集成
"""

from typing import Any, Dict, Union, cast

from src.config import ApiEndpointConfig
from src.modules.threat_intel.base_api import BaseApi


class ShodanApi(BaseApi):
    """Shodan API集成"""
    
    def __init__(self, api_key: str, config: ApiEndpointConfig):
        """
        初始化Shodan API
        
        Args:
            api_key: API密钥
            config: API配置
        """
        super().__init__("shodan", api_key, config)
    
    def _add_auth(self, headers: Dict[str, str]) -> bool:
        """
        添加认证信息到请求头
        
        Args:
            headers: 请求头字典
            
        Returns:
            bool: 是否成功添加认证信息
        """
        # Shodan API使用URL参数而不是请求头进行验证
        return True
    
    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP信息
        
        Args:
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        endpoint = f"/shodan/host/{ip}"
        params = {
            "key": self.api_key,
            "minify": False  # 获取完整信息
        }
        
        success, response, status_code = await self._request("GET", endpoint, params=params)
        
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
        查询URL信息（Shodan不直接支持URL查询）
        
        Args:
            url: URL
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": "Shodan不直接支持URL查询",
            "status_code": 0,
            "data": None
        }
    
    async def query_hash(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """
        查询文件哈希信息（Shodan不支持哈希查询）
        
        Args:
            hash_value: 哈希值
            hash_type: 哈希类型
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": "Shodan不支持文件哈希查询",
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
        
        # 提取基本信息
        ip = response.get("ip_str", "")
        hostnames = response.get("hostnames", [])
        domains = response.get("domains", [])
        country_code = response.get("country_code", "")
        country_name = response.get("country_name", "")
        city = response.get("city", "")
        isp = response.get("isp", "")
        org = response.get("org", "")
        asn = response.get("asn", "")
        last_update = response.get("last_update", "")
        
        # 提取开放端口
        ports = response.get("ports", [])
        
        # 提取地理位置信息
        latitude = None
        longitude = None
        if "latitude" in response and "longitude" in response:
            latitude = response["latitude"]
            longitude = response["longitude"]
        
        # 提取漏洞信息
        vulnerabilities = response.get("vulns", {})
        vuln_list = []
        if vulnerabilities:
            vuln_list = list(vulnerabilities.keys())
        
        # 提取标签
        tags = response.get("tags", [])
        
        # 计算威胁分数 - 基于漏洞数量和安全问题
        threat_score = 0.0
        
        # 如果有漏洞，增加威胁分数
        if vuln_list:
            # 根据漏洞数量调整威胁分数，最多加0.5
            vuln_score = min(len(vuln_list) / 10.0, 0.5)
            threat_score += vuln_score
        
        # 如果有特定标签，增加威胁分数
        dangerous_tags = ["malware", "botnet", "scanner", "proxy", "vpn", "tor"]
        for tag in tags:
            if tag.lower() in dangerous_tags:
                threat_score += 0.1
        
        # 限制最大威胁分数为1.0
        threat_score = min(threat_score, 1.0)
        
        # 提取服务信息
        services = []
        if "data" in response:
            for service in response["data"]:
                service_info = {
                    "port": service.get("port"),
                    "protocol": service.get("transport", ""),
                    "service": service.get("_shodan", {}).get("module", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", "")
                }
                
                # 如果存在HTTP信息，提取网站标题
                if "http" in service:
                    service_info["title"] = service.get("http", {}).get("title", "")
                
                services.append(service_info)
        
        # 标准化数据
        normalized = {
            "ip": ip,
            "hostnames": hostnames,
            "domains": domains,
            "country_code": country_code,
            "country_name": country_name,
            "city": city,
            "coordinates": {
                "latitude": latitude,
                "longitude": longitude
            } if latitude is not None and longitude is not None else {},
            "isp": isp,
            "org": org,
            "asn": asn,
            "last_update": last_update,
            "ports": ports,
            "services": services,
            "vulnerabilities": vuln_list,
            "tags": tags,
            "threat_score": threat_score,
            "raw": response
        }
        
        return normalized 