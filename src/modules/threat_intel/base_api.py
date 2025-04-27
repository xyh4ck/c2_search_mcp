"""
基础API封装类
"""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple, Union

import httpx

from src.config import ApiEndpointConfig
from src.modules.logging.logger import ServiceLogger


class BaseApi(ABC):
    """基础API封装类"""
    
    def __init__(self, api_name: str, api_key: str, config: ApiEndpointConfig):
        """
        初始化API
        
        Args:
            api_name: API名称
            api_key: API密钥
            config: API配置
        """
        self.api_name = api_name
        self.api_key = api_key
        self.config = config
        self.logger = ServiceLogger(f"api.{api_name}")
        self.base_url = config.base_url
        self.timeout = config.timeout
        self.retry_attempts = config.retry_attempts
    
    @abstractmethod
    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP信息
        
        Args:
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        pass
    
    @abstractmethod
    async def query_url(self, url: str) -> Dict[str, Any]:
        """
        查询URL信息
        
        Args:
            url: URL地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        pass
    
    @abstractmethod
    async def query_hash(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """
        查询哈希信息
        
        Args:
            hash_value: 哈希值
            hash_type: 哈希类型
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        pass
    
    async def _request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict[str, Any]] = None, 
        data: Optional[Dict[str, Any]] = None, 
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, Union[Dict[str, Any], str], int]:
        """
        发送API请求
        
        Args:
            method: 请求方法
            endpoint: 接口路径
            params: URL参数
            data: 表单数据
            json_data: JSON数据
            headers: 请求头
            
        Returns:
            Tuple[bool, Union[Dict[str, Any], str], int]: (是否成功, 响应数据或错误信息, 状态码)
        """
        url = f"{self.base_url}{endpoint}"
        
        # 添加默认请求头
        _headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        
        # 合并自定义请求头
        if headers:
            _headers.update(headers)
        
        # 添加API密钥
        if not self._add_auth(_headers):
            return False, "API密钥无效或未配置", 0
        
        start_time = time.time()
        status_code = 0
        
        for attempt in range(self.retry_attempts + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        data=data,
                        json=json_data,
                        headers=_headers
                    )
                    
                    status_code = response.status_code
                    
                    # 计算请求耗时
                    response_time = (time.time() - start_time) * 1000
                    
                    # 记录请求日志
                    self.logger.api_request(
                        api_name=self.api_name,
                        endpoint=endpoint,
                        status_code=status_code,
                        response_time=response_time
                    )
                    
                    # 检查响应状态
                    response.raise_for_status()
                    
                    # 解析响应数据
                    try:
                        response_data = response.json()
                        return True, response_data, status_code
                    except Exception as e:
                        # 无法解析为JSON
                        error_msg = f"无法解析响应为JSON: {str(e)}"
                        self.logger.error(error_msg)
                        return False, error_msg, status_code
                    
            except httpx.HTTPStatusError as e:
                status_code = e.response.status_code
                error_msg = f"HTTP错误: {status_code}"
                
                # 记录失败日志
                response_time = (time.time() - start_time) * 1000
                self.logger.api_request(
                    api_name=self.api_name,
                    endpoint=endpoint,
                    status_code=status_code,
                    response_time=response_time,
                    error=error_msg
                )
                
                # 对于特定状态码不进行重试
                if status_code in (400, 401, 403, 404, 422):
                    return False, f"请求失败: {error_msg}", status_code
                
                # 最后一次尝试失败
                if attempt == self.retry_attempts:
                    return False, f"请求失败: {error_msg}", status_code
                
                # 计算退避时间
                backoff_time = 2 ** attempt
                self.logger.warning(f"请求失败，将在 {backoff_time} 秒后重试")
                await asyncio.sleep(backoff_time)
                
            except httpx.RequestError as e:
                error_msg = f"请求错误: {str(e)}"
                
                # 记录失败日志
                response_time = (time.time() - start_time) * 1000
                self.logger.api_request(
                    api_name=self.api_name,
                    endpoint=endpoint,
                    status_code=10000,
                    response_time=response_time,
                    error=error_msg
                )
                
                # 最后一次尝试失败
                if attempt == self.retry_attempts:
                    return False, f"请求失败: {error_msg}", 0
                
                # 计算退避时间
                backoff_time = 2 ** attempt
                self.logger.warning(f"请求失败，将在 {backoff_time} 秒后重试")
                await asyncio.sleep(backoff_time)
                
            except Exception as e:
                error_msg = f"未知错误: {str(e)}"
                
                # 记录失败日志
                response_time = (time.time() - start_time) * 1000
                self.logger.api_request(
                    api_name=self.api_name,
                    endpoint=endpoint,
                    status_code=0,
                    response_time=response_time,
                    error=error_msg
                )
                
                return False, f"请求失败: {error_msg}", 0
        
        # 所有重试都失败
        return False, "请求失败，已达到最大重试次数", status_code
    
    def _add_auth(self, headers: Dict[str, str]) -> bool:
        """
        添加认证信息到请求头
        
        Args:
            headers: 请求头字典
            
        Returns:
            bool: 是否成功添加认证信息
        """
        # 检查API密钥是否有效
        if not self.api_key:
            self.logger.error(f"{self.api_name} API密钥未配置")
            return False
        
        # 由子类实现具体的认证方式
        return True
    
    def _process_error_response(self, error_msg: str, status_code: int) -> Dict[str, Any]:
        """
        处理错误响应
        
        Args:
            error_msg: 错误信息
            status_code: 状态码
            
        Returns:
            Dict[str, Any]: 标准化的错误响应
        """
        return {
            "api": self.api_name,
            "success": False,
            "error": error_msg,
            "status_code": status_code,
            "data": None
        } 