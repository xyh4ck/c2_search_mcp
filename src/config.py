"""
配置管理模块
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field


class ServerConfig(BaseModel):
    """服务器配置"""
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False


class LoggingConfig(BaseModel):
    """日志配置"""
    level: str = "INFO"
    file: str = "logs/threat_intel.log"
    rotation: str = "1 day"
    retention: str = "30 days"


class ApiKeyConfig(BaseModel):
    """API密钥配置"""
    virustotal: Optional[str] = None
    abuseipdb: Optional[str] = None
    hybrid_analysis: Optional[str] = None
    urlscan: Optional[str] = None
    ipinfo: Optional[str] = None


class ApiEndpointConfig(BaseModel):
    """API端点配置"""
    base_url: str
    timeout: int = 30
    retry_attempts: int = 3
    rate_limit: int = 10  # 请求/分钟


class ApiConfig(BaseModel):
    """API配置"""
    virustotal: ApiEndpointConfig
    abuseipdb: ApiEndpointConfig
    hybrid_analysis: ApiEndpointConfig
    urlscan: ApiEndpointConfig
    ipinfo: ApiEndpointConfig


class CacheConfig(BaseModel):
    """缓存配置"""
    enabled: bool = True
    ttl: int = 3600  # 缓存过期时间（秒）


class QueryConfig(BaseModel):
    """查询配置"""
    timeout: int = 60  # 单个查询超时时间（秒）
    cache: CacheConfig = Field(default_factory=CacheConfig)
    max_concurrent_requests: int = 10


class Config(BaseModel):
    """应用配置"""
    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    api_keys: ApiKeyConfig = Field(default_factory=ApiKeyConfig)
    api: ApiConfig
    query: QueryConfig = Field(default_factory=QueryConfig)


def load_config(config_path: str = "config.yaml") -> Config:
    """
    加载配置文件
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        Config: 配置对象
    """
    # 检查配置文件是否存在
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"配置文件 {config_path} 不存在")
    
    # 读取配置文件
    with open(config_path, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f)
    
    # 构建配置对象
    return Config(**config_data)


# 默认配置实例
config = load_config() if os.path.exists("config.yaml") else None 