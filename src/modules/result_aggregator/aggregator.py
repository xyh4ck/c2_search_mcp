"""
结果聚合器
"""

from collections import Counter
from typing import Any, Dict, List, Tuple

from src.modules.logging.logger import ServiceLogger


class ResultAggregator:
    """结果聚合器"""
    
    def __init__(self):
        """初始化结果聚合器"""
        self.logger = ServiceLogger("result_aggregator")
    
    def aggregate_ip_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        聚合IP查询结果
        
        Args:
            results: 各API的查询结果列表
            
        Returns:
            Dict[str, Any]: 聚合后的结果
        """
        if not results:
            return {"error": "无可用结果"}
        
        # 收集所有API结果
        api_results = {}
        for result in results:
            api_name = result.get("api", "unknown")
            api_results[api_name] = result
        
        # 提取基本信息
        ip = self._extract_ip_address(results)
        
        # 计算威胁分数
        threat_score, detection_rates = self._calculate_threat_score(results)
        
        # 收集地理位置信息
        geo_info = self._extract_geo_info(results)
        
        # 收集ASN信息
        asn_info = self._extract_asn_info(results)
        
        # 收集标签
        tags = self._extract_tags(results)
        
        # 收集分类信息
        categories = self._extract_categories(results)
        
        # 聚合结果
        aggregated_result = {
            "ip": ip,
            "threat_score": threat_score,
            "detection_rates": detection_rates,
            "geo_info": geo_info,
            "asn_info": asn_info,
            "tags": tags,
            "categories": categories,
            "api_results": api_results
        }
        
        return aggregated_result
    
    def aggregate_url_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        聚合URL查询结果
        
        Args:
            results: 各API的查询结果列表
            
        Returns:
            Dict[str, Any]: 聚合后的结果
        """
        if not results:
            return {"error": "无可用结果"}
        
        # 收集所有API结果
        api_results = {}
        for result in results:
            api_name = result.get("api", "unknown")
            api_results[api_name] = result
        
        # 提取URL
        url = self._extract_url(results)
        
        # 计算威胁分数
        threat_score, detection_rates = self._calculate_threat_score(results)
        
        # 收集标签
        tags = self._extract_tags(results)
        
        # 收集分类信息
        categories = self._extract_categories(results)
        
        # 提取网页标题
        title = self._extract_url_title(results)
        
        # 聚合结果
        aggregated_result = {
            "url": url,
            "threat_score": threat_score,
            "detection_rates": detection_rates,
            "title": title,
            "tags": tags,
            "categories": categories,
            "api_results": api_results
        }
        
        return aggregated_result
    
    def aggregate_hash_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        聚合哈希查询结果
        
        Args:
            results: 各API的查询结果列表
            
        Returns:
            Dict[str, Any]: 聚合后的结果
        """
        if not results:
            return {"error": "无可用结果"}
        
        # 收集所有API结果
        api_results = {}
        for result in results:
            api_name = result.get("api", "unknown")
            api_results[api_name] = result
        
        # 提取哈希值
        hash_values = self._extract_hash_values(results)
        
        # 计算威胁分数
        threat_score, detection_rates = self._calculate_threat_score(results)
        
        # 收集文件信息
        file_info = self._extract_file_info(results)
        
        # 收集标签
        tags = self._extract_tags(results)
        
        # 收集分类信息
        categories = self._extract_categories(results)
        
        # 聚合结果
        aggregated_result = {
            "hash_values": hash_values,
            "threat_score": threat_score,
            "detection_rates": detection_rates,
            "file_info": file_info,
            "tags": tags,
            "categories": categories,
            "api_results": api_results
        }
        
        return aggregated_result
    
    def _extract_ip_address(self, results: List[Dict[str, Any]]) -> str:
        """提取IP地址"""
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                if "ip" in data:
                    return data["ip"]
        return ""
    
    def _extract_url(self, results: List[Dict[str, Any]]) -> str:
        """提取URL"""
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                if "url" in data:
                    return data["url"]
        return ""
    
    def _extract_hash_values(self, results: List[Dict[str, Any]]) -> Dict[str, str]:
        """提取哈希值"""
        hash_values = {}
        
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                
                if "md5" in data and data["md5"]:
                    hash_values["md5"] = data["md5"]
                
                if "sha1" in data and data["sha1"]:
                    hash_values["sha1"] = data["sha1"]
                
                if "sha256" in data and data["sha256"]:
                    hash_values["sha256"] = data["sha256"]
        
        return hash_values
    
    def _calculate_threat_score(self, results: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Dict[str, int]]]:
        """
        计算威胁分数
        
        Returns:
            Tuple[float, Dict]: (威胁分数, 检测率)
        """
        total_score = 0.0
        score_count = 0
        detection_rates = {}
        
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                api_name = result.get("api", "unknown")
                
                if "threat_score" in data:
                    score = data["threat_score"]
                    if isinstance(score, (int, float)):
                        total_score += score
                        score_count += 1
                
                # 收集检测率
                if "engines_detected" in data and "engines_total" in data:
                    detected = data["engines_detected"]
                    total = data["engines_total"]
                    
                    if total > 0:
                        detection_rates[api_name] = {
                            "detected": detected,
                            "total": total,
                            "rate": detected / total
                        }
        
        # 计算平均威胁分数
        avg_threat_score = total_score / score_count if score_count > 0 else 0
        
        return avg_threat_score, detection_rates
    
    def _extract_geo_info(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """提取地理位置信息"""
        geo_info = {}
        
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                
                if "country" in data and data["country"]:
                    geo_info["country"] = data["country"]
                
                if "city" in data and data["city"]:
                    geo_info["city"] = data["city"]
                
                if "region" in data and data["region"]:
                    geo_info["region"] = data["region"]
                
                if "latitude" in data and "longitude" in data:
                    geo_info["coordinates"] = {
                        "latitude": data["latitude"],
                        "longitude": data["longitude"]
                    }
        
        return geo_info
    
    def _extract_asn_info(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """提取ASN信息"""
        asn_info = {}
        
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                
                if "asn" in data and data["asn"]:
                    asn_info["asn"] = data["asn"]
                
                if "as_owner" in data and data["as_owner"]:
                    asn_info["as_owner"] = data["as_owner"]
                
                if "isp" in data and data["isp"]:
                    asn_info["isp"] = data["isp"]
        
        return asn_info
    
    def _extract_tags(self, results: List[Dict[str, Any]]) -> List[str]:
        """提取标签"""
        all_tags = set()
        
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                
                if "tags" in data and isinstance(data["tags"], list):
                    all_tags.update(data["tags"])
        
        return sorted(list(all_tags))
    
    def _extract_categories(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """提取分类信息"""
        category_counter = Counter()
        
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                
                if "categories" in data and isinstance(data["categories"], dict):
                    for category, count in data["categories"].items():
                        category_counter[category] += count
        
        return dict(category_counter)
    
    def _extract_url_title(self, results: List[Dict[str, Any]]) -> str:
        """提取URL标题"""
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                
                if "title" in data and data["title"]:
                    return data["title"]
        
        return ""
    
    def _extract_file_info(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """提取文件信息"""
        file_info = {}
        
        for result in results:
            if result.get("success") and "data" in result:
                data = result["data"]
                
                if "file_type" in data and data["file_type"]:
                    file_info["type"] = data["file_type"]
                
                if "file_size" in data and data["file_size"]:
                    file_info["size"] = data["file_size"]
                
                if "file_name" in data and data["file_name"]:
                    file_info["name"] = data["file_name"]
                
                if "names" in data and isinstance(data["names"], list) and data["names"]:
                    file_info["alternative_names"] = data["names"]
        
        return file_info 