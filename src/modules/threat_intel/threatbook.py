"""
微步在线(ThreatBook) API集成
"""

from typing import Any, Dict, cast

from src.config import ApiEndpointConfig
from src.modules.logging.logger import ServiceLogger
from src.modules.threat_intel.base_api import BaseApi


class ThreatBookApi(BaseApi):
    """微步在线(ThreatBook) API集成"""

    def __init__(self, api_key: str, config: ApiEndpointConfig):
        """
        初始化ThreatBook API

        Args:
            api_key: API密钥
            config: API配置
        """
        super().__init__("threatbook", api_key, config)
        self.logger = ServiceLogger("api_provider")

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

        # ThreatBook API使用apikey作为URL参数，不需要在header中添加
        return True

    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP信息

        Args:
            ip: IP地址

        Returns:
            Dict[str, Any]: 查询结果
        """
        endpoint = "/ip/query"
        params = {"apikey": self.api_key, "resource": ip}

        success, response, status_code = await self._request(
            "GET", endpoint, params=params
        )

        if not success:
            return self._process_error_response(str(response), status_code)

        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_ip_response(cast(Dict[str, Any], response)),
        }
        self.logger.info(f"ThreatBook API查询IP信息结果: {result}")

        return result

    async def query_url(self, url: str) -> Dict[str, Any]:
        """
        查询URL信息

        Args:
            url: URL

        Returns:
            Dict[str, Any]: 查询结果
        """
        endpoint = "/url/report"
        params = {"apikey": self.api_key, "url": url}

        success, response, status_code = await self._request(
            "GET", endpoint, params=params
        )

        if not success:
            return self._process_error_response(str(response), status_code)

        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_url_response(cast(Dict[str, Any], response)),
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
        endpoint = "/file/report"
        params = {"apikey": self.api_key, "resource": hash_value}

        success, response, status_code = await self._request(
            "GET", endpoint, params=params
        )

        if not success:
            return self._process_error_response(str(response), status_code)

        # 标准化响应数据
        result = {
            "api": self.api_name,
            "success": True,
            "status_code": status_code,
            "data": self._normalize_file_response(cast(Dict[str, Any], response)),
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

        # 处理新的数据格式，IP作为键
        data = response.get("data", {})
        ip_address = next(iter(data.keys()), "")
        ip_data = data.get(ip_address, {})

        # 获取基本信息
        basic = ip_data.get("basic", {})

        # 获取ASN信息
        asn_info = ip_data.get("asn", {})

        # 根据ASN的rank值计算威胁分数
        # rank值范围为0-4，数值越大风险越高
        asn_rank = asn_info.get("rank", 0)
        threat_score = asn_rank / 4.0 if isinstance(asn_rank, (int, float)) else 0.0

        # 获取判断结果，用于丰富标签信息
        judgments = ip_data.get("judgments", [])
        is_malicious = False

        # 如果有判断结果，标记为潜在威胁
        if judgments and isinstance(judgments, list) and len(judgments) > 0:
            is_malicious = True

        # 从intelligences获取更多信息
        intelligences = ip_data.get("intelligences", {}).get("threatbook_lab", [])
        if intelligences and isinstance(intelligences, list):
            # 检查是否有未过期的情报
            active_intel = [
                intel for intel in intelligences if intel.get("expired") is False
            ]
            if active_intel:
                is_malicious = True

        # 提取标签
        tags = []
        if judgments and isinstance(judgments, list):
            tags.extend(judgments)

        # 提取标签类别
        tags_classes = ip_data.get("tags_classes", [])
        for tag_class in tags_classes:
            if isinstance(tag_class, dict) and "tags" in tag_class:
                tags.extend(tag_class.get("tags", []))

        # 获取位置信息
        location = basic.get("location", {})

        # 标准化数据
        normalized = {
            "ip": ip_address,
            "threat_score": threat_score,
            "severity": "",  # 这里不再使用severity字段
            "confidence_level": "",  # 新API格式中没有直接对应字段
            "is_malicious": is_malicious,
            "tags": tags,
            "update_time": ip_data.get("update_time", ""),
            "country": location.get("country", ""),
            "country_code": location.get("country_code", ""),
            "asn": str(asn_info.get("number", "")),
            "as_name": asn_info.get("info", ""),
            "categories": {},
            "raw": response,
        }

        # 提取分类信息
        scene = ip_data.get("scene", "")
        if scene:
            normalized["categories"][scene] = 1

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

        data = response.get("data", {})
        basic = data.get("basic", {})

        # 计算威胁分数
        severity = data.get("severity", "")
        threat_score = 0.0
        if severity == "high":
            threat_score = 0.9
        elif severity == "medium":
            threat_score = 0.6
        elif severity == "low":
            threat_score = 0.3

        # 提取标签
        tags = []
        judgments = data.get("judgments", [])
        if isinstance(judgments, list):
            tags.extend(judgments)

        # 标准化数据
        normalized = {
            "url": basic.get("url", ""),
            "threat_score": threat_score,
            "severity": severity,
            "confidence_level": data.get("confidence_level", ""),
            "is_malicious": data.get("is_malicious", False),
            "tags": tags,
            "update_time": data.get("update_time", ""),
            "categories": {},
            "raw": response,
        }

        # 提取分类信息
        scene = data.get("scene", "")
        if scene:
            normalized["categories"][scene] = 1

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

        data = response.get("data", {})

        # 网络指标
        network_info = {
            "domains": data.get("network", {}).get("domains"),
            "hosts": data.get("network", {}).get("hosts"),
        }

        # 标准化数据
        normalized = {
            "summary": data.get("summary", ""),
            "multiengines": data.get("multiengines", ""),
            "static_analysis": data.get("static").get("basic",""),
            "network_info": network_info
        }

        return normalized
