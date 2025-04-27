"""
AbuseIPDB API集成
"""

from typing import Any, Dict, cast

from src.config import ApiEndpointConfig
from src.modules.threat_intel.base_api import BaseApi


class AbuseIPDBApi(BaseApi):
    """AbuseIPDB API集成"""
    
    def __init__(self, api_key: str, config: ApiEndpointConfig):
        """
        初始化AbuseIPDB API
        
        Args:
            api_key: API密钥
            config: API配置
        """
        super().__init__("abuseipdb", api_key, config)
    
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
        
        headers["Key"] = self.api_key
        return True
    
    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP信息
        
        Args:
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        endpoint = "/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
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
        查询URL信息 (AbuseIPDB不支持URL查询)
        
        Args:
            url: URL
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": "AbuseIPDB不支持URL查询",
            "status_code": 0,
            "data": None
        }
    
    async def query_hash(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """
        查询文件哈希信息 (AbuseIPDB不支持哈希查询)
        
        Args:
            hash_value: 哈希值
            hash_type: 哈希类型
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": "AbuseIPDB不支持文件哈希查询",
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
        if not response or "data" not in response:
            return {"raw": response}
        
        data = response["data"]
        
        # 计算威胁分数 (AbuseConfidenceScore转换为0-1之间的值)
        abuse_score = data.get("abuseConfidenceScore", 0)
        threat_score = min(abuse_score / 100.0, 1.0)
        
        # 提取报告信息
        total_reports = data.get("totalReports", 0)
        
        # 域名信息
        domain = data.get("domain", "")
        
        # 提取地理位置信息
        country_code = data.get("countryCode", "")
        country_name = data.get("countryName", "")
        
        # 使用情况类型
        usage_type = data.get("usageType", "")
        
        # 提取ISP信息
        isp = data.get("isp", "")
        
        # 提取报告的分类
        categories = {}
        if "reports" in data:
            for report in data["reports"]:
                for category in report.get("categories", []):
                    if category not in categories:
                        categories[category] = 0
                    categories[category] += 1
        
        # 标准化数据结构
        normalized = {
            "ip": data.get("ipAddress", ""),
            "threat_score": threat_score,
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "country": country_name,
            "country_code": country_code,
            "isp": isp,
            "usage_type": usage_type,
            "domain": domain,
            "is_whitelisted": data.get("isWhitelisted", False),
            "last_reported_at": data.get("lastReportedAt", ""),
            "categories": categories,
            "raw": response
        }
        
        return normalized 