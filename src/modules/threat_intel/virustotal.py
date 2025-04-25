"""
VirusTotal API集成
"""

from typing import Any, Dict

from src.config import ApiEndpointConfig
from src.modules.threat_intel.base_api import BaseApi


class VirusTotalApi(BaseApi):
    """VirusTotal API集成"""
    
    def __init__(self, api_key: str, config: ApiEndpointConfig):
        """
        初始化VirusTotal API
        
        Args:
            api_key: API密钥
            config: API配置
        """
        super().__init__("virustotal", api_key, config)
    
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
        
        headers["x-apikey"] = self.api_key
        return True
    
    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP信息
        
        Args:
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        endpoint = f"/ip_addresses/{ip}"
        
        success, response, status_code = await self._request("GET", endpoint)
        
        if not success:
            return self._process_error_response(response, status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_ip_response(response)
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
        import base64
        
        # URL需要进行Base64编码
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        endpoint = f"/urls/{encoded_url}"
        
        success, response, status_code = await self._request("GET", endpoint)
        
        if not success:
            # 如果未找到，可能需要先提交URL
            if status_code == 404:
                submit_success, submit_response, submit_status_code = await self._submit_url(url)
                if submit_success:
                    # 等待分析完成后重新查询
                    self.logger.info(f"URL {url} 已提交分析，等待结果")
                    return {
                        "api": self.api_name,
                        "success": True,
                        "status_code": submit_status_code,
                        "data": {
                            "message": "URL已提交分析，请稍后查询",
                            "url": url,
                            "analysis_status": "queued"
                        }
                    }
            
            return self._process_error_response(response, status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_url_response(response)
        }
        
        return result
    
    async def _submit_url(self, url: str) -> tuple:
        """
        提交URL进行分析
        
        Args:
            url: URL
            
        Returns:
            tuple: (成功标志, 响应数据, 状态码)
        """
        endpoint = "/urls"
        data = {"url": url}
        
        return await self._request("POST", endpoint, data=data)
    
    async def query_hash(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """
        查询文件哈希信息
        
        Args:
            hash_value: 哈希值
            hash_type: 哈希类型
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        endpoint = f"/files/{hash_value}"
        
        success, response, status_code = await self._request("GET", endpoint)
        
        if not success:
            return self._process_error_response(response, status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_file_response(response)
        }
        
        return result
    
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
        attributes = data.get("attributes", {})
        
        # 提取检测结果
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        total_votes = attributes.get("total_votes", {})
        
        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        community_score = 0
        
        if "harmless" in total_votes and "malicious" in total_votes:
            harmless_votes = total_votes["harmless"]
            malicious_votes = total_votes["malicious"]
            total_votes_count = harmless_votes + malicious_votes
            if total_votes_count > 0:
                community_score = malicious_votes / total_votes_count
        
        # 计算威胁分数
        engines_count = sum(last_analysis_stats.values())
        threat_score = 0
        if engines_count > 0:
            threat_score = (malicious_count + (suspicious_count * 0.5)) / engines_count
        
        # 提取国家信息
        country = attributes.get("country")
        
        normalized = {
            "ip": data.get("id"),
            "engines_detected": malicious_count,
            "engines_total": engines_count,
            "community_score": community_score,
            "threat_score": threat_score,
            "country": country,
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "tags": attributes.get("tags", []),
            "reputation": attributes.get("reputation", 0),
            "categories": {},
            "raw": response
        }
        
        # 提取分类信息
        categories = attributes.get("categories", {})
        for engine, category in categories.items():
            if category not in normalized["categories"]:
                normalized["categories"][category] = 0
            normalized["categories"][category] += 1
        
        return normalized
    
    def _normalize_url_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        标准化URL响应数据
        
        Args:
            response: API响应
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        if not response or "data" not in response:
            return {"raw": response}
        
        data = response["data"]
        attributes = data.get("attributes", {})
        
        # 提取检测结果
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        total_votes = attributes.get("total_votes", {})
        
        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        community_score = 0
        
        if "harmless" in total_votes and "malicious" in total_votes:
            harmless_votes = total_votes["harmless"]
            malicious_votes = total_votes["malicious"]
            total_votes_count = harmless_votes + malicious_votes
            if total_votes_count > 0:
                community_score = malicious_votes / total_votes_count
        
        # 计算威胁分数
        engines_count = sum(last_analysis_stats.values())
        threat_score = 0
        if engines_count > 0:
            threat_score = (malicious_count + (suspicious_count * 0.5)) / engines_count
        
        normalized = {
            "url": attributes.get("url"),
            "engines_detected": malicious_count,
            "engines_total": engines_count,
            "community_score": community_score,
            "threat_score": threat_score,
            "last_analysis_date": attributes.get("last_analysis_date"),
            "tags": attributes.get("tags", []),
            "categories": {},
            "title": attributes.get("title", ""),
            "final_url": attributes.get("last_final_url", ""),
            "raw": response
        }
        
        # 提取分类信息
        categories = attributes.get("categories", {})
        for engine, category in categories.items():
            if category not in normalized["categories"]:
                normalized["categories"][category] = 0
            normalized["categories"][category] += 1
        
        return normalized
    
    def _normalize_file_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        标准化文件哈希响应数据
        
        Args:
            response: API响应
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        if not response or "data" not in response:
            return {"raw": response}
        
        data = response["data"]
        attributes = data.get("attributes", {})
        
        # 提取检测结果
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        malicious_count = last_analysis_stats.get("malicious", 0)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        
        # 计算威胁分数
        engines_count = sum(last_analysis_stats.values())
        threat_score = 0
        if engines_count > 0:
            threat_score = (malicious_count + (suspicious_count * 0.5)) / engines_count
        
        normalized = {
            "hash": data.get("id"),
            "md5": attributes.get("md5"),
            "sha1": attributes.get("sha1"),
            "sha256": attributes.get("sha256"),
            "engines_detected": malicious_count,
            "engines_total": engines_count,
            "threat_score": threat_score,
            "file_type": attributes.get("type_description", ""),
            "file_size": attributes.get("size"),
            "file_name": attributes.get("meaningful_name", ""),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "first_submission_date": attributes.get("first_submission_date"),
            "names": attributes.get("names", []),
            "raw": response
        }
        
        return normalized 