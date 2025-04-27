"""
URLScan.io API集成
"""

from typing import Any, Dict, cast

from src.config import ApiEndpointConfig
from src.modules.threat_intel.base_api import BaseApi


class URLScanApi(BaseApi):
    """URLScan.io API集成"""
    
    def __init__(self, api_key: str, config: ApiEndpointConfig):
        """
        初始化URLScan.io API
        
        Args:
            api_key: API密钥
            config: API配置
        """
        super().__init__("urlscan", api_key, config)
    
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
        
        headers["API-Key"] = self.api_key
        return True
    
    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP信息 (使用搜索API)
        
        Args:
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        endpoint = "/search"
        params = {
            "q": f"ip:{ip}"
        }
        
        success, response, status_code = await self._request("GET", endpoint, params=params)
        
        if not success:
            return self._process_error_response(str(response), status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_ip_search_response(cast(Dict[str, Any], response), ip)
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
        # 首先尝试搜索这个URL
        search_result = await self._search_url(url)
        
        # 如果搜索找到了结果，直接返回
        if search_result.get("success") and search_result.get("data", {}).get("has_results", False):
            return search_result
        
        # 如果搜索没有结果，提交URL进行扫描
        scan_result = await self._submit_scan(url)
        
        # 如果提交成功，等待扫描完成
        if scan_result.get("success"):
            scan_id = scan_result.get("data", {}).get("uuid")
            if scan_id:
                # 提供异步结果
                return {
                    "api": self.api_name,
                    "success": True,
                    "status_code": 200,
                    "data": {
                        "message": "URL已提交扫描，请稍后查询",
                        "url": url,
                        "scan_id": scan_id,
                        "scan_status": "pending",
                        "result_url": f"https://urlscan.io/result/{scan_id}/",
                        "api_url": f"{self.base_url}/result/{scan_id}/"
                    }
                }
        
        # 如果提交失败，返回错误
        return scan_result
    
    async def _search_url(self, url: str) -> Dict[str, Any]:
        """
        搜索URL信息
        
        Args:
            url: URL
            
        Returns:
            Dict[str, Any]: 搜索结果
        """
        endpoint = "/search"
        params = {
            "q": f"page.url:{url} OR task.url:{url}"
        }
        
        success, response, status_code = await self._request("GET", endpoint, params=params)
        
        if not success:
            return self._process_error_response(str(response), status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_url_search_response(cast(Dict[str, Any], response), url)
        }
        
        return result
    
    async def _submit_scan(self, url: str) -> Dict[str, Any]:
        """
        提交URL进行扫描
        
        Args:
            url: URL
            
        Returns:
            Dict[str, Any]: 提交结果
        """
        endpoint = "/scan/"
        json_data = {
            "url": url,
            "visibility": "public"
        }
        
        success, response, status_code = await self._request("POST", endpoint, json_data=json_data)
        
        if not success:
            return self._process_error_response(str(response), status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": cast(Dict[str, Any], response)
        }
        
        return result
    
    async def _get_scan_result(self, scan_id: str) -> Dict[str, Any]:
        """
        获取扫描结果
        
        Args:
            scan_id: 扫描ID
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        endpoint = f"/result/{scan_id}/"
        
        success, response, status_code = await self._request("GET", endpoint)
        
        if not success:
            return self._process_error_response(str(response), status_code)
        
        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_url_result(cast(Dict[str, Any], response))
        }
        
        return result
    
    async def query_hash(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """
        查询文件哈希信息 (URLScan.io不直接支持哈希查询)
        
        Args:
            hash_value: 哈希值
            hash_type: 哈希类型
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": "URLScan.io不支持文件哈希查询",
            "status_code": 0,
            "data": None
        }
    
    def _normalize_ip_search_response(self, response: Dict[str, Any], ip: str) -> Dict[str, Any]:
        """
        标准化IP搜索响应数据
        
        Args:
            response: API响应
            ip: 搜索的IP
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        if not response or "results" not in response:
            return {"raw": response, "has_results": False}
        
        results = response.get("results", [])
        total_results = response.get("total", 0)
        
        if not results or total_results == 0:
            return {"raw": response, "has_results": False, "ip": ip}
        
        # 收集所有关联域名
        domains = set()
        urls = set()
        countries = set()
        asns = set()
        
        for result in results:
            page = result.get("page", {})
            domain = page.get("domain")
            if domain:
                domains.add(domain)
            
            url = page.get("url")
            if url:
                urls.add(url)
            
            country = result.get("country")
            if country:
                countries.add(country)
            
            asn_name = result.get("asn")
            if asn_name:
                asns.add(asn_name)
        
        # 标准化数据
        normalized = {
            "ip": ip,
            "has_results": True,
            "total_results": total_results,
            "associated_domains": list(domains),
            "associated_urls": list(urls),
            "countries": list(countries),
            "asns": list(asns),
            "first_seen": results[0].get("task", {}).get("time") if results else None,
            "last_seen": results[-1].get("task", {}).get("time") if results else None,
            "raw": response
        }
        
        return normalized
    
    def _normalize_url_search_response(self, response: Dict[str, Any], url: str) -> Dict[str, Any]:
        """
        标准化URL搜索响应数据
        
        Args:
            response: API响应
            url: 搜索的URL
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        if not response or "results" not in response:
            return {"raw": response, "has_results": False}
        
        results = response.get("results", [])
        total_results = response.get("total", 0)
        
        if not results or total_results == 0:
            return {"raw": response, "has_results": False, "url": url}
        
        # 使用最新的结果
        latest_result = results[0]
        
        # 提取相关数据
        page = latest_result.get("page", {})
        task = latest_result.get("task", {})
        stats = latest_result.get("stats", {})
        
        # 标准化数据
        normalized = {
            "url": url,
            "has_results": True,
            "total_results": total_results,
            "final_url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "asn": latest_result.get("asn"),
            "country": latest_result.get("country"),
            "server": page.get("server"),
            "status": page.get("status"),
            "scan_date": task.get("time"),
            "categories": {},
            "tags": [],
            "threat_score": 0.0,  # URLScan没有直接的威胁分数，后续可以基于标记计算
            "malicious": latest_result.get("malicious", False),
            "stats": {
                "uniq_countries": stats.get("uniqCountries"),
                "console_msgs": stats.get("consolemsgs"),
                "domains": stats.get("domains"),
                "links": stats.get("links")
            },
            "result_url": f"https://urlscan.io/result/{task.get('uuid')}/",
            "raw": response
        }
        
        return normalized
    
    def _normalize_url_result(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        标准化URL结果响应数据
        
        Args:
            response: API响应
            
        Returns:
            Dict[str, Any]: 标准化后的数据
        """
        if not response or "task" not in response:
            return {"raw": response}
        
        # 提取相关数据
        page = response.get("page", {})
        task = response.get("task", {})
        stats = response.get("stats", {})
        meta = response.get("meta", {})
        verdicts = response.get("verdicts", {})
        
        # 计算威胁分数
        threat_score = 0.0
        malicious = verdicts.get("overall", {}).get("malicious", False)
        if malicious:
            threat_score = 0.8  # 如果判定为恶意，给予较高的分数
        
        # 提取标签
        tags = verdicts.get("overall", {}).get("tags", [])
        
        # 标准化数据
        normalized = {
            "url": task.get("url"),
            "final_url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "asn": meta.get("processors", {}).get("asn", {}).get("asn"),
            "as_name": meta.get("processors", {}).get("asn", {}).get("as_name"),
            "country": meta.get("processors", {}).get("geo", {}).get("country"),
            "server": page.get("server"),
            "status": page.get("status"),
            "title": page.get("title"),
            "scan_date": task.get("time"),
            "categories": {},
            "tags": tags,
            "threat_score": threat_score,
            "malicious": malicious,
            "stats": {
                "uniq_countries": stats.get("uniqCountries"),
                "console_msgs": stats.get("consolemsgs"),
                "domains": stats.get("domains"),
                "links": stats.get("links")
            },
            "result_url": f"https://urlscan.io/result/{task.get('uuid')}/",
            "screenshot_url": f"https://urlscan.io/screenshots/{task.get('uuid')}.png",
            "raw": response
        }
        
        return normalized 