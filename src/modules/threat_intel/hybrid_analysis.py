"""
Hybrid Analysis API集成
"""

from typing import Any, Dict, Union, cast

from src.config import ApiEndpointConfig
from src.modules.threat_intel.base_api import BaseApi


class HybridAnalysisApi(BaseApi):
    """Hybrid Analysis API集成"""
    
    def __init__(self, api_key: str, config: ApiEndpointConfig):
        """
        初始化Hybrid Analysis API
        
        Args:
            api_key: API密钥
            config: API配置
        """
        super().__init__("hybrid_analysis", api_key, config)
    
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
        
        headers["api-key"] = self.api_key
        # Hybrid Analysis需要指定User-Agent
        headers["User-Agent"] = "ThreatIntelMCP-HybridAnalysis/1.0.0"
        return True
    
    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP信息 (Hybrid Analysis不直接支持IP查询)
        
        Args:
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": "Hybrid Analysis不直接支持IP查询",
            "status_code": 0,
            "data": None
        }
    
    async def query_url(self, url: str) -> Dict[str, Any]:
        """
        查询URL信息 (Hybrid Analysis不直接支持URL查询)
        
        Args:
            url: URL
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": "Hybrid Analysis不直接支持URL查询",
            "status_code": 0,
            "data": None
        }
    
    async def query_hash(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """
        查询文件哈希信息
        
        Args:
            hash_value: 哈希值
            hash_type: 哈希类型
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        endpoint = "/search/hash"
        params = {
            "hash": hash_value
        }
        
        success, response, status_code = await self._request("GET", endpoint, params=params)
        
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
    
    async def _get_report_summary(self, report_id: str) -> Dict[str, Any]:
        """
        获取报告摘要
        
        Args:
            report_id: 报告ID
            
        Returns:
            Dict[str, Any]: 报告摘要
        """
        endpoint = f"/report/{report_id}/summary"
        
        success, response, status_code = await self._request("GET", endpoint)
        
        if not success:
            return self._process_error_response(str(response), status_code)
        
        return {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": cast(Dict[str, Any], response)
        }
    
    def _normalize_hash_response(self, response: Any, hash_value: str) -> Dict[str, Any]:
        """
        标准化哈希响应数据
        
        Args:
            response: API响应
            hash_value: 哈希值
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        # Hybrid Analysis返回的是一个列表
        if not isinstance(response, list):
            return {"raw": response, "hash": hash_value}
        
        if not response:
            return {"raw": response, "hash": hash_value, "found": False}
        
        # 使用最新的分析结果
        latest_result = response[0]
        
        # 提取威胁分数
        # Hybrid Analysis使用0-100的威胁分数，我们将其转换为0-1
        threat_level = latest_result.get("threat_level")
        threat_score = 0.0
        
        if threat_level == "no specific threat":
            threat_score = 0.0
        elif threat_level == "suspicious":
            threat_score = 0.5
        elif threat_level == "malicious":
            threat_score = 1.0
        else:
            # 使用威胁分数 (如果有)
            if "threat_score" in latest_result:
                threat_score = float(latest_result.get("threat_score", 0)) / 100.0
        
        # 提取文件类型和名称
        file_type = latest_result.get("type", "")
        file_name = latest_result.get("submit_name", "")
        
        # 提取VT检测率
        vt_detect = latest_result.get("vt_detect", 0)
        vt_total = latest_result.get("vt_total", 0)
        
        # 提取标签
        tags = []
        if "tags" in latest_result:
            tags = latest_result["tags"]
        
        # 标准化数据
        normalized = {
            "hash": hash_value,
            "found": True,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "file_type": file_type,
            "file_name": file_name,
            "environment": latest_result.get("environment", ""),
            "analysis_start_time": latest_result.get("analysis_start_time", ""),
            "total_signatures": latest_result.get("total_signatures", 0),
            "total_processes": latest_result.get("total_processes", 0),
            "total_network_connections": latest_result.get("total_network_connections", 0),
            "vt_detect": vt_detect,
            "vt_total": vt_total,
            "tags": tags,
            "verdict": latest_result.get("verdict", ""),
            "report_url": latest_result.get("permalink", ""),
            "raw": response
        }
        
        # 添加检测率
        if vt_total > 0:
            normalized["detection_rate"] = {
                "virustotal": {
                    "detected": vt_detect,
                    "total": vt_total,
                    "rate": vt_detect / vt_total if vt_total > 0 else 0
                }
            }
        
        return normalized 