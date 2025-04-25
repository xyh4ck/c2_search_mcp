"""
CVE-Search 服务
提供CVE漏洞数据查询和管理功能的服务层
"""

from typing import Dict, Any, List, Optional, Union
import logging

from ..adapters.cve_search_adapter import CVESearchAdapter
from ..formatters.cve_search_formatter import CVESearchFormatter


class CVESearchService:
    """
    CVE-Search 服务类
    
    连接适配器和格式化器，提供完整的CVE数据服务功能
    """
    
    def __init__(self, api_url: str, api_key: Optional[str] = None):
        """
        初始化CVE-Search服务
        
        Args:
            api_url: CVE-Search API的基础URL
            api_key: 可选的API密钥
        """
        self.adapter = CVESearchAdapter(api_url, api_key)
        self.formatter = CVESearchFormatter()
        self.logger = logging.getLogger(__name__)
    
    async def get_vendors(self) -> List[str]:
        """
        获取所有供应商列表
        
        Returns:
            List[str]: 供应商列表
        """
        try:
            response = await self.adapter.get_vendors()
            return self.formatter.format_vendors(response)
        except Exception as e:
            self.logger.error(f"获取供应商列表失败: {str(e)}")
            return []
    
    async def get_vendor_products(self, vendor: str) -> List[str]:
        """
        获取指定供应商的产品列表
        
        Args:
            vendor: 供应商名称
            
        Returns:
            List[str]: 产品列表
        """
        try:
            response = await self.adapter.get_vendor_products(vendor)
            return self.formatter.format_products(response)
        except Exception as e:
            self.logger.error(f"获取供应商产品列表失败: {str(e)}")
            return []
    
    async def get_vendor_product_vulnerabilities(self, vendor: str, product: str) -> List[Dict[str, Any]]:
        """
        获取指定供应商和产品的漏洞列表
        
        Args:
            vendor: 供应商名称
            product: 产品名称
            
        Returns:
            List[Dict[str, Any]]: 漏洞列表
        """
        try:
            response = await self.adapter.get_vendor_product_vulnerabilities(vendor, product)
            return self.formatter.format_vulnerabilities(response)
        except Exception as e:
            self.logger.error(f"获取漏洞列表失败: {str(e)}")
            return []
    
    async def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        获取指定CVE ID的详细信息
        
        Args:
            cve_id: CVE ID，例如 CVE-2021-44228
            
        Returns:
            Dict[str, Any]: CVE详细信息
        """
        try:
            response = await self.adapter.get_cve_details(cve_id)
            return self.formatter.format_cve_details(response)
        except Exception as e:
            self.logger.error(f"获取CVE详情失败: {str(e)}")
            return {}
    
    async def get_latest_vulnerabilities(self, limit: int = 30) -> List[Dict[str, Any]]:
        """
        获取最新的漏洞列表
        
        Args:
            limit: 返回的漏洞数量，默认30个
            
        Returns:
            List[Dict[str, Any]]: 最新漏洞列表
        """
        try:
            response = await self.adapter.get_latest_vulnerabilities(limit)
            return self.formatter.format_vulnerabilities(response)
        except Exception as e:
            self.logger.error(f"获取最新漏洞列表失败: {str(e)}")
            return []
    
    async def get_database_status(self) -> Dict[str, Any]:
        """
        获取数据库状态信息
        
        Returns:
            Dict[str, Any]: 数据库状态信息
        """
        try:
            response = await self.adapter.get_database_status()
            return self.formatter.format_database_status(response)
        except Exception as e:
            self.logger.error(f"获取数据库状态失败: {str(e)}")
            return {}
    
    async def search_vulnerabilities(self, keyword: str) -> List[Dict[str, Any]]:
        """
        按关键词搜索漏洞
        
        Args:
            keyword: 搜索关键词
            
        Returns:
            List[Dict[str, Any]]: 匹配的漏洞列表
        """
        try:
            response = await self.adapter.search_vulnerabilities(keyword)
            return self.formatter.format_vulnerabilities(response)
        except Exception as e:
            self.logger.error(f"搜索漏洞失败: {str(e)}")
            return []
    
    async def get_cpe_vulnerabilities(self, cpe: str) -> List[Dict[str, Any]]:
        """
        获取指定CPE的漏洞列表
        
        Args:
            cpe: CPE字符串
            
        Returns:
            List[Dict[str, Any]]: 漏洞列表
        """
        try:
            response = await self.adapter.get_cpe_vulnerabilities(cpe)
            return self.formatter.format_vulnerabilities(response)
        except Exception as e:
            self.logger.error(f"获取CPE相关漏洞失败: {str(e)}")
            return [] 