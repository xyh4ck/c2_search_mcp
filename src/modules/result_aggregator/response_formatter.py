"""
MCP响应格式化模块
"""

import json
from typing import Any, Dict


class MCPResponseFormatter:
    """MCP响应格式化器"""
    
    @staticmethod
    def format_response(query_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        格式化MCP响应
        
        Args:
            query_result: 查询结果
            
        Returns:
            Dict[str, Any]: 格式化后的MCP响应
        """
        # 提取基本信息
        status = query_result.get("status", "error")
        query_type = query_result.get("query_type", "unknown")
        query_value = query_result.get("query_value", "")
        execution_time = query_result.get("execution_time_ms", 0)
        
        # 如果查询失败，返回错误信息
        if status == "error":
            error = query_result.get("error", "Unknown error")
            return {
                "status": "error",
                "error": error,
                "query": {
                    "type": query_type,
                    "value": query_value
                },
                "execution_time_ms": execution_time
            }
        
        # 提取查询数据
        data = query_result.get("data", {})
        
        # 根据查询类型格式化响应
        if query_type == "ip":
            response_data = MCPResponseFormatter._format_ip_response(data)
        elif query_type == "url":
            response_data = MCPResponseFormatter._format_url_response(data)
        elif query_type == "hash":
            response_data = MCPResponseFormatter._format_hash_response(data)
        else:
            response_data = {"error": "Unsupported query type"}
            status = "error"
        
        # 构建最终响应
        response = {
            "status": status,
            "query": {
                "type": query_type,
                "value": query_value
            },
            "data": response_data,
            "execution_time_ms": execution_time
        }
        
        return response
    
    @staticmethod
    def _format_ip_response(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        格式化IP响应数据
        
        Args:
            data: IP查询结果数据
            
        Returns:
            Dict[str, Any]: 格式化后的IP响应数据
        """
        # 提取IP基本信息
        ip = data.get("ip", "")
        threat_score = data.get("threat_score", 0)
        
        # 提取地理信息
        geo_info = data.get("geo_info", {})
        
        # 提取ASN信息
        asn_info = data.get("asn_info", {})
        
        # 提取标签和分类
        tags = data.get("tags", [])
        categories = data.get("categories", {})
        
        # 提取检测率
        detection_rates = data.get("detection_rates", {})
        
        # 移除原始API响应以减小返回数据大小
        api_results = {}
        for api_name, api_result in data.get("api_results", {}).items():
            if "data" in api_result and "raw" in api_result["data"]:
                # 创建没有原始数据的API结果副本
                api_result_copy = api_result.copy()
                if "data" in api_result_copy:
                    data_copy = api_result_copy["data"].copy()
                    if "raw" in data_copy:
                        del data_copy["raw"]
                    api_result_copy["data"] = data_copy
                api_results[api_name] = api_result_copy
            else:
                api_results[api_name] = api_result
        
        # 构建格式化响应
        formatted_response = {
            "ip": ip,
            "threat_summary": {
                "score": threat_score,
                "level": MCPResponseFormatter._get_threat_level(threat_score),
                "tags": tags,
                "categories": categories,
                "detection_rates": detection_rates
            },
            "geo_info": geo_info,
            "network_info": asn_info,
            "api_results": api_results
        }
        
        return formatted_response
    
    @staticmethod
    def _format_url_response(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        格式化URL响应数据
        
        Args:
            data: URL查询结果数据
            
        Returns:
            Dict[str, Any]: 格式化后的URL响应数据
        """
        # 提取URL基本信息
        url = data.get("url", "")
        threat_score = data.get("threat_score", 0)
        title = data.get("title", "")
        
        # 提取标签和分类
        tags = data.get("tags", [])
        categories = data.get("categories", {})
        
        # 提取检测率
        detection_rates = data.get("detection_rates", {})
        
        # 移除原始API响应以减小返回数据大小
        api_results = {}
        for api_name, api_result in data.get("api_results", {}).items():
            if "data" in api_result and "raw" in api_result["data"]:
                # 创建没有原始数据的API结果副本
                api_result_copy = api_result.copy()
                if "data" in api_result_copy:
                    data_copy = api_result_copy["data"].copy()
                    if "raw" in data_copy:
                        del data_copy["raw"]
                    api_result_copy["data"] = data_copy
                api_results[api_name] = api_result_copy
            else:
                api_results[api_name] = api_result
        
        # 构建格式化响应
        formatted_response = {
            "url": url,
            "title": title,
            "threat_summary": {
                "score": threat_score,
                "level": MCPResponseFormatter._get_threat_level(threat_score),
                "tags": tags,
                "categories": categories,
                "detection_rates": detection_rates
            },
            "api_results": api_results
        }
        
        return formatted_response
    
    @staticmethod
    def _format_hash_response(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        格式化哈希响应数据
        
        Args:
            data: 哈希查询结果数据
            
        Returns:
            Dict[str, Any]: 格式化后的哈希响应数据
        """
        # 提取哈希基本信息
        hash_values = data.get("hash_values", {})
        threat_score = data.get("threat_score", 0)
        
        # 提取文件信息
        file_info = data.get("file_info", {})
        
        # 提取标签和分类
        tags = data.get("tags", [])
        categories = data.get("categories", {})
        
        # 提取检测率
        detection_rates = data.get("detection_rates", {})
        
        # 移除原始API响应以减小返回数据大小
        api_results = {}
        for api_name, api_result in data.get("api_results", {}).items():
            if "data" in api_result and "raw" in api_result["data"]:
                # 创建没有原始数据的API结果副本
                api_result_copy = api_result.copy()
                if "data" in api_result_copy:
                    data_copy = api_result_copy["data"].copy()
                    if "raw" in data_copy:
                        del data_copy["raw"]
                    api_result_copy["data"] = data_copy
                api_results[api_name] = api_result_copy
            else:
                api_results[api_name] = api_result
        
        # 构建格式化响应
        formatted_response = {
            "hash_values": hash_values,
            "file_info": file_info,
            "threat_summary": {
                "score": threat_score,
                "level": MCPResponseFormatter._get_threat_level(threat_score),
                "tags": tags,
                "categories": categories,
                "detection_rates": detection_rates
            },
            "api_results": api_results
        }
        
        return formatted_response
    
    @staticmethod
    def _get_threat_level(score: float) -> str:
        """
        根据威胁分数获取威胁等级
        
        Args:
            score: 威胁分数(0-1)
            
        Returns:
            str: 威胁等级
        """
        if score < 0.2:
            return "low"
        elif score < 0.5:
            return "medium"
        elif score < 0.8:
            return "high"
        else:
            return "critical" 