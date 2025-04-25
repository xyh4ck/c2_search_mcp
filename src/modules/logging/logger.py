"""
日志管理模块
"""

import os
import sys
from pathlib import Path
from typing import Dict, Union, List, Any, Optional, Tuple

from loguru import logger

from src.config import LoggingConfig
from src.modules.logging.log_store import LogStore


def setup_logger(config: LoggingConfig) -> None:
    """
    配置日志记录器
    
    Args:
        config: 日志配置对象
    """
    # 创建日志目录
    log_dir = Path(config.file).parent
    if not log_dir.exists():
        log_dir.mkdir(parents=True, exist_ok=True)
    
    # 清除默认处理程序
    logger.remove()
    
    # 添加控制台处理程序
    logger.add(
        sys.stderr,
        level=config.level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )
    
    # 添加文件处理程序
    logger.add(
        config.file,
        level=config.level,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation=config.rotation,
        retention=config.retention,
        compression="zip",
        encoding="utf-8"
    )
    
    logger.info(f"日志系统初始化完成，级别: {config.level}, 文件: {config.file}")


class ServiceLogger:
    """服务日志记录器"""
    
    def __init__(self, service_name: str, db_path: Optional[str] = None):
        """
        初始化服务日志记录器
        
        Args:
            service_name: 服务名称
            db_path: 日志存储数据库路径，如果为None则不启用日志存储
        """
        self.service_name = service_name
        self.logger = logger.bind(service=service_name)
        
        # 初始化日志存储
        self.log_store = None
        if db_path:
            self.log_store = LogStore(db_path)
            self.logger.info(f"已启用日志存储，数据库: {db_path}")
    
    def debug(self, message: str, **kwargs):
        """记录调试日志"""
        self.logger.debug(message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """记录信息日志"""
        self.logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """记录警告日志"""
        self.logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """记录错误日志"""
        self.logger.error(message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """记录严重错误日志"""
        self.logger.critical(message, **kwargs)
    
    def api_request(self, api_name: str, endpoint: str, status_code: int, response_time: float, error: str = None, extra_data: Optional[Dict[str, Any]] = None):
        """
        记录API请求日志
        
        Args:
            api_name: API名称
            endpoint: 端点
            status_code: 状态码
            response_time: 响应时间（毫秒）
            error: 错误信息
            extra_data: 额外数据
        """
        log_data = {
            "api": api_name,
            "endpoint": endpoint,
            "status_code": status_code,
            "response_time_ms": response_time
        }
        
        if error:
            log_data["error"] = error
            self.error(f"API请求失败: {api_name} {endpoint}", **log_data)
        else:
            self.info(f"API请求成功: {api_name} {endpoint}", **log_data)
        
        # 存储到数据库
        if self.log_store:
            self.log_store.store_api_request(
                api_name=api_name,
                endpoint=endpoint,
                status_code=status_code,
                response_time=response_time,
                error=error,
                service=self.service_name,
                extra_data=extra_data
            )
    
    def query_log(self, query_type: str, query_value: str, client_ip: str, success: bool, duration: float, error: str = None, extra_data: Optional[Dict[str, Any]] = None):
        """
        记录查询日志
        
        Args:
            query_type: 查询类型
            query_value: 查询值
            client_ip: 客户端IP
            success: 是否成功
            duration: 查询耗时（毫秒）
            error: 错误信息
            extra_data: 额外数据
        """
        log_data = {
            "query_type": query_type,
            "query_value": query_value,
            "client_ip": client_ip,
            "success": success,
            "duration_ms": duration
        }
        
        if error:
            log_data["error"] = error
            self.error(f"查询失败: {query_type}={query_value}", **log_data)
        else:
            self.info(f"查询成功: {query_type}={query_value}", **log_data)
        
        # 存储到数据库
        if self.log_store:
            self.log_store.store_query_log(
                query_type=query_type,
                query_value=query_value,
                client_ip=client_ip,
                success=success,
                duration=duration,
                error=error,
                service=self.service_name,
                extra_data=extra_data
            )
            
    def search_api_logs(self, **kwargs) -> Tuple[List[Dict[str, Any]], int]:
        """
        搜索API请求日志
        
        Args:
            **kwargs: 搜索参数，参考LogStore.search_api_logs方法
            
        Returns:
            Tuple[List[Dict[str, Any]], int]: 结果列表和总记录数
        """
        if not self.log_store:
            return [], 0
        
        return self.log_store.search_api_logs(**kwargs)
    
    def search_query_logs(self, **kwargs) -> Tuple[List[Dict[str, Any]], int]:
        """
        搜索查询日志
        
        Args:
            **kwargs: 搜索参数，参考LogStore.search_query_logs方法
            
        Returns:
            Tuple[List[Dict[str, Any]], int]: 结果列表和总记录数
        """
        if not self.log_store:
            return [], 0
        
        return self.log_store.search_query_logs(**kwargs)
    
    def get_api_stats(self, days: int = 30) -> Dict[str, Any]:
        """
        获取API调用统计信息
        
        Args:
            days: 统计天数
            
        Returns:
            Dict[str, Any]: 统计信息
        """
        if not self.log_store:
            return {}
        
        return self.log_store.get_api_stats(days)
    
    def get_query_stats(self, days: int = 30) -> Dict[str, Any]:
        """
        获取查询统计信息
        
        Args:
            days: 统计天数
            
        Returns:
            Dict[str, Any]: 统计信息
        """
        if not self.log_store:
            return {}
        
        return self.log_store.get_query_stats(days) 