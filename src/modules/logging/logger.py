"""
日志管理模块
"""

import sys
from pathlib import Path

from loguru import logger

from src.config import LoggingConfig


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
    
    def __init__(self, service_name: str):
        """
        初始化服务日志记录器
        
        Args:
            service_name: 服务名称
        """
        self.service_name = service_name
        self.logger = logger.bind(service=service_name)

    
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
    
    def api_request(self, api_name: str, endpoint: str, status_code: int, response_time: float, error: str = None):
        """
        记录API请求日志
        
        Args:
            api_name: API名称
            endpoint: 端点
            status_code: 状态码
            response_time: 响应时间（毫秒）
            error: 错误信息
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
