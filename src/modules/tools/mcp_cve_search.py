"""
CVE-Search MCP工具实现
"""

import json
from typing import Dict, Any, List, Optional

from modules.adapters.cve_search_adapter import CVESearchAdapter
from modules.result_aggregator.cve_search_formatter import CVESearchFormatter
from modules.tools.abstract_tool import AbstractTool


class MCPCVESearchTool(AbstractTool):
    """
    CVE-Search MCP工具实现
    
    提供与CVE-Search API交互的方法，用于获取和处理漏洞信息
    """

    def __init__(self, cve_search_url: str, api_key: Optional[str] = None) -> None:
        """
        初始化CVE-Search工具
        
        Args:
            cve_search_url: CVE-Search API的基础URL
            api_key: 用于验证的API密钥（可选）
        """
        super().__init__()
        self.adapter = CVESearchAdapter(cve_search_url, api_key)
        self.formatter = CVESearchFormatter()
        
    async def get_vendors(self) -> Dict[str, Any]:
        """
        获取所有供应商列表
        
        Returns:
            Dict[str, Any]: 供应商信息
        """
        response = await self.adapter.get_vendors()
        return self.formatter.format_response(response, "vendors")
    
    async def get_vendor_products(self, vendor: str) -> Dict[str, Any]:
        """
        获取指定供应商的所有产品
        
        Args:
            vendor: 供应商名称
            
        Returns:
            Dict[str, Any]: 产品信息
        """
        response = await self.adapter.get_vendor_products(vendor)
        return self.formatter.format_response(response, "vendor_products")
    
    async def get_vendor_product_vulnerabilities(self, vendor: str, product: str) -> Dict[str, Any]:
        """
        获取指定供应商和产品的所有漏洞
        
        Args:
            vendor: 供应商名称
            product: 产品名称
            
        Returns:
            Dict[str, Any]: 漏洞信息
        """
        response = await self.adapter.get_vendor_product_vulnerabilities(vendor, product)
        return self.formatter.format_response(response, "vendor_product_vulnerabilities")
    
    async def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        获取指定CVE ID的详细信息
        
        Args:
            cve_id: CVE ID，如"CVE-2021-44228"
            
        Returns:
            Dict[str, Any]: CVE详细信息
        """
        response = await self.adapter.get_cve_details(cve_id)
        return self.formatter.format_response(response, "cve")
    
    async def get_latest_vulnerabilities(self, limit: int = 30) -> Dict[str, Any]:
        """
        获取最新的漏洞信息
        
        Args:
            limit: 返回结果数量限制，默认30
            
        Returns:
            Dict[str, Any]: 最新漏洞信息
        """
        response = await self.adapter.get_latest_vulnerabilities(limit)
        return self.formatter.format_response(response, "latest")
    
    async def get_database_status(self) -> Dict[str, Any]:
        """
        获取数据库状态信息
        
        Returns:
            Dict[str, Any]: 数据库状态信息
        """
        response = await self.adapter.get_database_status()
        return self.formatter.format_response(response, "db_status")
    
    async def search_vulnerabilities(self, query: str) -> Dict[str, Any]:
        """
        搜索漏洞信息
        
        Args:
            query: 搜索查询字符串
            
        Returns:
            Dict[str, Any]: 搜索结果
        """
        response = await self.adapter.search_vulnerabilities(query)
        return self.formatter.format_response(response, "vulnerabilities")
    
    async def get_cpe_vulnerabilities(self, cpe: str) -> Dict[str, Any]:
        """
        获取指定CPE的漏洞信息
        
        Args:
            cpe: CPE字符串，如"cpe:/a:apache:log4j:2.0"
            
        Returns:
            Dict[str, Any]: 漏洞信息
        """
        response = await self.adapter.get_cpe_vulnerabilities(cpe)
        return self.formatter.format_response(response, "vulnerabilities") 