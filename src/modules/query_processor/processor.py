"""
查询处理器
"""

import asyncio
import time
from typing import Any, Dict

from src.config import Config
from src.modules.logging.logger import ServiceLogger
from src.modules.query_processor.validator import QueryValidator
from src.modules.result_aggregator.aggregator import ResultAggregator
from src.modules.threat_intel.api_provider import APIProvider


class QueryProcessor:
    """查询处理器"""

    def __init__(self, config: Config):
        """
        初始化查询处理器
        
        Args:
            config: 应用配置
        """
        self.config = config
        self.logger = ServiceLogger("query_processor")
        self.validator = QueryValidator()
        self.api_provider = APIProvider(config)
        self.aggregator = ResultAggregator()

    async def process_query(self, query_type: str, query_value: str) -> Dict[str, Any]:
        """
        处理查询请求
        
        Args:
            query_type: 查询类型
            query_value: 查询值

        Returns:
            Dict[str, Any]: 查询结果
        """
        start_time = time.time()

        # 验证查询参数
        is_valid, error = self.validator.validate_query(query_type, query_value)
        if not is_valid:
            return {
                "status": "error",
                "error": error,
                "query_type": query_type,
                "query_value": query_value
            }

        try:
            # 路由到相应的处理方法
            if query_type == "ip":
                result = await self._process_ip_query(query_value)
            elif query_type == "url":
                result = await self._process_url_query(query_value)
            elif query_type == "hash":
                result = await self._process_hash_query(query_value)
            else:
                raise ValueError(f"不支持的查询类型: {query_type}")

            # 记录查询日志
            duration = (time.time() - start_time) * 1000

            return {
                "status": "success",
                "query_type": query_type,
                "query_value": query_value,
                "data": result,
                "execution_time_ms": duration
            }

        except Exception as e:
            # 记录错误日志
            duration = (time.time() - start_time) * 1000
            error_msg = str(e)

            return {
                "status": "error",
                "error": error_msg,
                "query_type": query_type,
                "query_value": query_value,
                "execution_time_ms": duration
            }

    async def _process_ip_query(self, ip: str) -> Dict[str, Any]:
        """
        处理IP查询
        
        Args:
            ip: IP地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        self.logger.info(f"开始查询IP: {ip}")

        # 获取支持IP查询的API列表
        ip_apis = self.api_provider.get_apis_for_ip_query()

        if not ip_apis:
            self.logger.warning("没有可用的IP查询API")
            return {"error": "没有可用的IP查询API"}

        # 并发查询所有API
        tasks = []
        for api in ip_apis:
            tasks.append(api.query_ip(ip))

        # 等待所有查询完成
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 过滤掉异常结果，并记录错误日志
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"API查询出错: {ip_apis[i].api_name} - {str(result)}")
            else:
                valid_results.append(result)

        # 聚合结果
        if not valid_results:
            self.logger.warning(f"IP查询 {ip} 没有获取到有效结果")
            return {"error": "没有有效的查询结果"}

        self.logger.info(f"IP查询 {ip} 成功，共获取 {len(valid_results)} 个结果")
        return self.aggregator.aggregate_ip_results(valid_results)

    async def _process_url_query(self, url: str) -> Dict[str, Any]:
        """
        处理URL查询
        
        Args:
            url: URL地址
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        self.logger.info(f"开始查询URL: {url}")

        # 获取支持URL查询的API列表
        url_apis = self.api_provider.get_apis_for_url_query()

        if not url_apis:
            self.logger.warning("没有可用的URL查询API")
            return {"error": "没有可用的URL查询API"}

        # 并发查询所有API
        tasks = []
        for api in url_apis:
            tasks.append(api.query_url(url))

        # 等待所有查询完成
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 过滤掉异常结果，并记录错误日志
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"API查询出错: {url_apis[i].api_name} - {str(result)}")
            else:
                valid_results.append(result)

        # 聚合结果
        if not valid_results:
            self.logger.warning(f"URL查询 {url} 没有获取到有效结果")
            return {"error": "没有有效的查询结果"}

        self.logger.info(f"URL查询 {url} 成功，共获取 {len(valid_results)} 个结果")
        return self.aggregator.aggregate_url_results(valid_results)

    async def _process_hash_query(self, hash_value: str) -> Dict[str, Any]:
        """
        处理哈希查询
        
        Args:
            hash_value: 哈希值
            
        Returns:
            Dict[str, Any]: 查询结果
        """
        self.logger.info(f"开始查询哈希: {hash_value}")

        # 确定哈希类型
        hash_type = self._determine_hash_type(hash_value)
        self.logger.info(f"哈希类型: {hash_type}")

        # 获取支持哈希查询的API列表
        hash_apis = self.api_provider.get_apis_for_hash_query()

        if not hash_apis:
            self.logger.warning("没有可用的哈希查询API")
            return {"error": "没有可用的哈希查询API"}

        # 并发查询所有API
        tasks = []
        for api in hash_apis:
            tasks.append(api.query_hash(hash_value, hash_type))

        # 等待所有查询完成
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 过滤掉异常结果，并记录错误日志
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"API查询出错: {hash_apis[i].api_name} - {str(result)}")
            else:
                valid_results.append(result)

        # 聚合结果
        if not valid_results:
            self.logger.warning(f"哈希查询 {hash_value} 没有获取到有效结果")
            return {"error": "没有有效的查询结果"}

        self.logger.info(f"哈希查询 {hash_value} 成功，共获取 {len(valid_results)} 个结果")
        return self.aggregator.aggregate_hash_results(valid_results)

    def _determine_hash_type(self, hash_value: str) -> str:
        """
        确定哈希类型
        
        Args:
            hash_value: 哈希值
            
        Returns:
            str: 哈希类型(md5/sha1/sha256)
        """
        length = len(hash_value)

        if length == 32:
            return "md5"
        elif length == 40:
            return "sha1"
        elif length == 64:
            return "sha256"
        else:
            return "unknown"
