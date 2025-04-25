"""
CVE-Search 适配器
负责与CVE-Search API进行通信的适配器
"""

import aiohttp
from typing import Dict, Any, List, Optional, Union
import logging
import urllib.parse


class CVESearchAdapter:
    """
    CVE-Search API适配器
    
    负责与CVE-Search API通信，获取和提交数据
    """
    
    def __init__(self, api_url: str, api_key: Optional[str] = None):
        """
        初始化CVE-Search适配器
        
        Args:
            api_url: CVE-Search API的基础URL
            api_key: 可选的API密钥，某些API可能需要授权
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)
        
        # 设置请求头
        self.headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'CVESearch-Client/1.0'
        }
        
        # 如果有API密钥，添加到请求头
        if self.api_key:
            self.headers['Authorization'] = f'Bearer {self.api_key}'
    
    async def _make_request(self, endpoint: str, method: str = 'GET', params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        向API发送请求
        
        Args:
            endpoint: API端点路径
            method: HTTP方法，默认为GET
            params: 请求参数
            
        Returns:
            Dict[str, Any]: API响应数据
        
        Raises:
            Exception: 请求失败时抛出异常
        """
        url = f"{self.api_url}{endpoint}"
        
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                if method == 'GET':
                    async with session.get(url, params=params) as response:
                        if response.status != 200:
                            self.logger.error(f"API请求失败: {url} - 状态码: {response.status}")
                            return {}
                        return await response.json()
                elif method == 'POST':
                    async with session.post(url, json=params) as response:
                        if response.status != 200:
                            self.logger.error(f"API请求失败: {url} - 状态码: {response.status}")
                            return {}
                        return await response.json()
                else:
                    self.logger.error(f"不支持的HTTP方法: {method}")
                    return {}
        except aiohttp.ClientError as e:
            self.logger.error(f"API连接错误: {str(e)}")
            raise Exception(f"API连接错误: {str(e)}")
        except Exception as e:
            self.logger.error(f"API请求异常: {str(e)}")
            raise Exception(f"API请求异常: {str(e)}")
    
    async def get_vendors(self) -> Dict[str, Any]:
        """
        获取所有供应商列表
        
        Returns:
            Dict[str, Any]: 供应商列表响应
        """
        return await self._make_request('/browse/vendor')
    
    async def get_vendor_products(self, vendor: str) -> Dict[str, Any]:
        """
        获取指定供应商的产品列表
        
        Args:
            vendor: 供应商名称
            
        Returns:
            Dict[str, Any]: 产品列表响应
        """
        encoded_vendor = urllib.parse.quote(vendor)
        return await self._make_request(f'/browse/vendor/{encoded_vendor}')
    
    async def get_vendor_product_vulnerabilities(self, vendor: str, product: str) -> Dict[str, Any]:
        """
        获取指定供应商和产品的漏洞列表
        
        Args:
            vendor: 供应商名称
            product: 产品名称
            
        Returns:
            Dict[str, Any]: 漏洞列表响应
        """
        encoded_vendor = urllib.parse.quote(vendor)
        encoded_product = urllib.parse.quote(product)
        return await self._make_request(f'/search/{encoded_vendor}/{encoded_product}')
    
    async def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        获取指定CVE ID的详细信息
        
        Args:
            cve_id: CVE ID，例如 CVE-2021-44228
            
        Returns:
            Dict[str, Any]: CVE详细信息响应
        """
        return await self._make_request(f'/cve/{cve_id}')
    
    async def get_latest_vulnerabilities(self, limit: int = 30) -> Dict[str, Any]:
        """
        获取最新的漏洞列表
        
        Args:
            limit: 返回的漏洞数量，默认30个
            
        Returns:
            Dict[str, Any]: 最新漏洞列表响应
        """
        return await self._make_request(f'/last/{limit}')
    
    async def get_database_status(self) -> Dict[str, Any]:
        """
        获取数据库状态信息
        
        Returns:
            Dict[str, Any]: 数据库状态信息响应
        """
        return await self._make_request('/dbInfo')
    
    async def search_vulnerabilities(self, keyword: str) -> Dict[str, Any]:
        """
        按关键词搜索漏洞
        
        Args:
            keyword: 搜索关键词
            
        Returns:
            Dict[str, Any]: 搜索结果响应
        """
        encoded_keyword = urllib.parse.quote(keyword)
        return await self._make_request(f'/search/{encoded_keyword}')
    
    async def get_cpe_vulnerabilities(self, cpe: str) -> Dict[str, Any]:
        """
        获取指定CPE的漏洞列表
        
        Args:
            cpe: CPE字符串
            
        Returns:
            Dict[str, Any]: 漏洞列表响应
        """
        encoded_cpe = urllib.parse.quote(cpe)
        return await self._make_request(f'/cpe/{encoded_cpe}') 