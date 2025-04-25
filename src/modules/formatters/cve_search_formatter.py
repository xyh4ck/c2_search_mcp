"""
CVE-Search 响应格式化器
负责将CVE-Search API的响应数据转换为适合客户端使用的格式
"""

from typing import Dict, Any, List, Optional, Union
from datetime import datetime


class CVESearchFormatter:
    """
    CVE-Search 响应数据格式化器
    
    用于处理和转换CVE-Search API的响应数据
    """
    
    @staticmethod
    def format_vendors(response: Dict[str, Any]) -> List[str]:
        """
        格式化供应商列表响应
        
        Args:
            response: 原始API响应数据
            
        Returns:
            List[str]: 格式化后的供应商列表
        """
        if isinstance(response, dict) and "data" in response and isinstance(response["data"], list):
            return response["data"]
        elif isinstance(response, list):
            return response
        else:
            return []
    
    @staticmethod
    def format_products(response: Dict[str, Any]) -> List[str]:
        """
        格式化产品列表响应
        
        Args:
            response: 原始API响应数据
            
        Returns:
            List[str]: 格式化后的产品列表
        """
        if isinstance(response, dict) and "data" in response and isinstance(response["data"], list):
            return response["data"]
        elif isinstance(response, list):
            return response
        else:
            return []
    
    @staticmethod
    def format_vulnerabilities(response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        格式化漏洞列表响应
        
        Args:
            response: 原始API响应数据
            
        Returns:
            List[Dict[str, Any]]: 格式化后的漏洞列表
        """
        vulnerabilities = []
        
        # 处理可能的不同响应格式
        if isinstance(response, dict):
            if "data" in response and isinstance(response["data"], list):
                items = response["data"]
            elif "results" in response and isinstance(response["results"], list):
                items = response["results"]
            else:
                items = [response] if "id" in response or "cve" in response else []
        elif isinstance(response, list):
            items = response
        else:
            items = []
        
        for item in items:
            if not isinstance(item, dict):
                continue
                
            vulnerability = {}
            
            # 提取基本信息
            vulnerability["id"] = item.get("id") or item.get("cve", {}).get("id") or item.get("cve_id", "")
            vulnerability["published"] = CVESearchFormatter._format_date(item.get("Published") or item.get("published", ""))
            vulnerability["modified"] = CVESearchFormatter._format_date(item.get("Modified") or item.get("modified", ""))
            vulnerability["summary"] = item.get("summary") or item.get("description", "")
            
            # 提取CVSS信息
            cvss = item.get("cvss", None)
            if cvss:
                vulnerability["cvss"] = {
                    "score": cvss.get("score", 0.0),
                    "vector": cvss.get("vector", ""),
                    "version": cvss.get("version", "")
                }
            
            # 提取CWE信息
            if "cwe" in item and item["cwe"]:
                if isinstance(item["cwe"], str):
                    vulnerability["cwe"] = [item["cwe"]]
                elif isinstance(item["cwe"], list):
                    vulnerability["cwe"] = item["cwe"]
            
            # 提取参考链接
            references = item.get("references", [])
            if references:
                vulnerability["references"] = references
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    @staticmethod
    def format_cve_details(response: Dict[str, Any]) -> Dict[str, Any]:
        """
        格式化CVE详情响应
        
        Args:
            response: 原始API响应数据
            
        Returns:
            Dict[str, Any]: 格式化后的CVE详情
        """
        if not isinstance(response, dict):
            return {}
        
        # 如果响应是空的或错误的
        if not response or "error" in response:
            return {}
        
        result = {}
        
        # 基本信息
        result["id"] = response.get("id", "")
        result["summary"] = response.get("summary", "")
        result["published"] = CVESearchFormatter._format_date(response.get("Published", ""))
        result["modified"] = CVESearchFormatter._format_date(response.get("Modified", ""))
        
        # CVSS信息
        if "cvss" in response:
            result["cvss"] = {
                "score": response["cvss"].get("score", 0.0),
                "vector": response["cvss"].get("vector", ""),
                "version": response["cvss"].get("version", "3.0")
            }
        
        # CWE信息
        if "cwe" in response and response["cwe"]:
            if isinstance(response["cwe"], str):
                result["cwe"] = [response["cwe"]]
            elif isinstance(response["cwe"], list):
                result["cwe"] = response["cwe"]
        
        # 影响的厂商和产品
        if "vulnerable_product" in response and response["vulnerable_product"]:
            result["vulnerable_products"] = response["vulnerable_product"]
        
        # 参考链接
        if "references" in response and response["references"]:
            result["references"] = response["references"]
        
        # 漏洞评分
        if "impact" in response:
            result["impact"] = response["impact"]
        
        return result
    
    @staticmethod
    def format_database_status(response: Dict[str, Any]) -> Dict[str, Any]:
        """
        格式化数据库状态响应
        
        Args:
            response: 原始API响应数据
            
        Returns:
            Dict[str, Any]: 格式化后的数据库状态信息
        """
        if not isinstance(response, dict):
            return {"status": "error", "message": "Invalid response format"}
        
        result = {}
        
        # 添加数据库信息
        if "dbInfo" in response:
            info = response["dbInfo"]
            db_info = {}
            
            for key, value in info.items():
                if key in ["db", "name"]:
                    db_info["name"] = value
                elif key in ["last_update", "updated"]:
                    db_info["last_update"] = CVESearchFormatter._format_date(value)
                elif "size" in key:
                    db_info["size"] = value
                else:
                    db_info[key] = value
            
            result["databases"] = db_info
        
        # 添加更多数据库统计信息
        if "stats" in response:
            result["statistics"] = response["stats"]
        
        return result
    
    @staticmethod
    def _format_date(date_str: str) -> str:
        """
        格式化日期字符串
        
        Args:
            date_str: 原始日期字符串
            
        Returns:
            str: 格式化后的日期字符串 (YYYY-MM-DD HH:MM:SS)
        """
        if not date_str:
            return ""
        
        try:
            # 尝试解析多种可能的日期格式
            for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"]:
                try:
                    dt = datetime.strptime(date_str, fmt)
                    return dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
            
            # 如果上面的格式都不匹配，尝试更宽松的解析
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            # 如果无法解析，返回原始字符串
            return date_str 