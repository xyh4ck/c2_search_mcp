"""
ThreatFox API集成
"""

from typing import Any, Dict, Union, cast

from src.config import ApiEndpointConfig
from src.modules.threat_intel.base_api import BaseApi


class ThreatFoxApi(BaseApi):
    """ThreatFox API集成"""
    
    def __init__(self, api_key: str, config: ApiEndpointConfig):
        """
        初始化ThreatFox API
        
        Args:
            api_key: API密钥
            config: API配置
        """
        super().__init__("threatfox", api_key, config)
    
    def _add_auth(self, headers: Dict[str, str]) -> bool:
        """
        添加认证信息到请求头
        
        Args:
            headers: 请求头字典
            
        Returns:
            bool: 是否成功添加认证信息
        """
        # ThreatFox使用POST请求中的HTTP请求体来验证，所以这里返回True
        return True
    
    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP信息
        
        Args:
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        # 构建请求体
        json_data = {
            "query": "search_ioc",
            "search_term": ip,
            "api_key": self.api_key
        }
        
        success, response, status_code = await self._request("POST", "", json_data=json_data)
        
        if not success:
            return self._process_error_response(str(response), status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_ip_response(cast(Dict[str, Any], response), ip)
        }
        
        return result
    
    async def query_url(self, url: str) -> Dict[str, Any]:
        """
        查询URL信息
        
        Args:
            url: URL
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        # 构建请求体
        json_data = {
            "query": "search_ioc",
            "search_term": url,
            "api_key": self.api_key
        }
        
        success, response, status_code = await self._request("POST", "", json_data=json_data)
        
        if not success:
            return self._process_error_response(str(response), status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_url_response(cast(Dict[str, Any], response), url)
        }
        
        return result
    
    async def query_hash(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """
        查询文件哈希信息
        
        Args:
            hash_value: 哈希值
            hash_type: 哈希类型
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        # 构建请求体
        json_data = {
            "query": "search_ioc",
            "search_term": hash_value,
            "api_key": self.api_key
        }
        
        success, response, status_code = await self._request("POST", "", json_data=json_data)
        
        if not success:
            return self._process_error_response(str(response), status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_hash_response(cast(Dict[str, Any], response), hash_value)
        }
        
        return result
    
    def _normalize_ip_response(self, response: Dict[str, Any], ip: str) -> Dict[str, Any]:
        """
        标准化IP响应数据
        
        Args:
            response: API响应
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        return self._normalize_common_response(response, ip, "ip")
    
    def _normalize_url_response(self, response: Dict[str, Any], url: str) -> Dict[str, Any]:
        """
        标准化URL响应数据
        
        Args:
            response: API响应
            url: URL
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        return self._normalize_common_response(response, url, "url")
    
    def _normalize_hash_response(self, response: Dict[str, Any], hash_value: str) -> Dict[str, Any]:
        """
        标准化哈希响应数据
        
        Args:
            response: API响应
            hash_value: 哈希值
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        return self._normalize_common_response(response, hash_value, "hash")
    
    def _normalize_common_response(self, response: Dict[str, Any], ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """
        标准化通用响应数据
        
        Args:
            response: API响应
            ioc_value: IOC值
            ioc_type: IOC类型
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        if not response:
            return {"raw": response}
        
        # 检查查询状态
        query_status = response.get("query_status")
        if query_status != "ok":
            error_msg = response.get("data", {}).get("error", "Unknown error")
            return {
                "error": error_msg,
                "raw": response
            }
        
        # 提取数据
        data = response.get("data", [])
        
        if not data:
            return {
                ioc_type: ioc_value,
                "found": False,
                "raw": response
            }
        
        # 收集所有威胁情报
        malware_families = set()
        tags = set()
        countries = set()
        threat_types = set()
        first_seen = None
        last_seen = None
        
        for item in data:
            if "malware" in item:
                malware_families.add(item["malware"])
            
            if "tags" in item:
                for tag in item["tags"]:
                    tags.add(tag)
            
            if "ioc_type" in item:
                threat_types.add(item["ioc_type"])
            
            if "reporter" in item and "country" in item["reporter"]:
                countries.add(item["reporter"]["country"])
            
            # 追踪最早和最晚的记录时间
            if "first_seen" in item:
                first_seen_time = item["first_seen"]
                if first_seen is None or first_seen_time < first_seen:
                    first_seen = first_seen_time
            
            if "last_seen" in item:
                last_seen_time = item["last_seen"]
                if last_seen is None or last_seen_time > last_seen:
                    last_seen = last_seen_time
        
        # 构建标准化响应
        normalized = {
            ioc_type: ioc_value,
            "found": True,
            "malware_families": list(malware_families),
            "tags": list(tags),
            "countries": list(countries),
            "threat_types": list(threat_types),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "total_results": len(data),
            "confidence": 1.0 if data else 0.0,  # ThreatFox中发现意味着高置信度
            "threat_score": 0.8 if data else 0.0,  # ThreatFox中发现通常表示较高的威胁
            "raw": response
        }
        
        return normalized 