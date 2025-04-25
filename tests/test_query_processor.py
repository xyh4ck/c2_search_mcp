"""
查询处理器测试
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import Config
from src.modules.query_processor.processor import QueryProcessor
from src.modules.result_aggregator.aggregator import ResultAggregator


class TestQueryProcessor:
    """查询处理器测试"""
    
    @pytest.fixture
    def mock_config(self):
        """模拟配置"""
        config = MagicMock(spec=Config)
        config.api_keys = MagicMock()
        config.api_keys.virustotal = "dummy_vt_key"
        config.api_keys.abuseipdb = "dummy_abuseipdb_key"
        config.api_keys.ipinfo = "dummy_ipinfo_key"
        
        config.api = MagicMock()
        for api_name in ["virustotal", "abuseipdb", "hybrid_analysis", "urlscan", "threatfox", "ipinfo", "shodan"]:
            setattr(config.api, api_name, MagicMock())
            getattr(config.api, api_name).base_url = f"https://{api_name}.com/api"
            getattr(config.api, api_name).timeout = 30
            getattr(config.api, api_name).retry_attempts = 3
        
        return config
    
    @pytest.fixture
    def mock_api_provider(self):
        """模拟API提供者"""
        with patch("src.modules.threat_intel.api_provider.APIProvider") as MockAPIProvider:
            api_provider = MockAPIProvider.return_value
            
            # 模拟IP查询API
            mock_vt_api = AsyncMock()
            mock_vt_api.api_name = "virustotal"
            mock_vt_api.query_ip = AsyncMock(return_value={
                "api": "virustotal",
                "success": True,
                "status_code": 200,
                "data": {
                    "ip": "8.8.8.8",
                    "threat_score": 0.1,
                    "country": "US"
                }
            })
            
            mock_abuseipdb_api = AsyncMock()
            mock_abuseipdb_api.api_name = "abuseipdb"
            mock_abuseipdb_api.query_ip = AsyncMock(return_value={
                "api": "abuseipdb",
                "success": True,
                "status_code": 200,
                "data": {
                    "ip": "8.8.8.8",
                    "threat_score": 0.0,
                    "country": "US"
                }
            })
            
            # 模拟URL查询API
            mock_urlscan_api = AsyncMock()
            mock_urlscan_api.api_name = "urlscan"
            mock_urlscan_api.query_url = AsyncMock(return_value={
                "api": "urlscan",
                "success": True,
                "status_code": 200,
                "data": {
                    "url": "https://example.com",
                    "threat_score": 0.0,
                    "title": "Example Domain"
                }
            })
            
            # 模拟哈希查询API
            mock_vt_api.query_hash = AsyncMock(return_value={
                "api": "virustotal",
                "success": True,
                "status_code": 200,
                "data": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "threat_score": 0.0,
                    "file_type": "text"
                }
            })
            
            # 设置API提供者的返回值
            api_provider.get_apis_for_ip_query.return_value = [mock_vt_api, mock_abuseipdb_api]
            api_provider.get_apis_for_url_query.return_value = [mock_vt_api, mock_urlscan_api]
            api_provider.get_apis_for_hash_query.return_value = [mock_vt_api]
            
            yield api_provider
    
    @pytest.fixture
    def query_processor(self, mock_config, mock_api_provider):
        """创建查询处理器实例"""
        with patch("src.modules.threat_intel.api_provider.APIProvider", return_value=mock_api_provider):
            processor = QueryProcessor(mock_config)
            yield processor
    
    @pytest.mark.asyncio
    async def test_process_ip_query(self, query_processor, mock_api_provider):
        """测试IP查询处理"""
        # 模拟结果聚合器
        with patch.object(ResultAggregator, "aggregate_ip_results") as mock_aggregate:
            mock_aggregate.return_value = {
                "ip": "8.8.8.8", 
                "threat_score": 0.05, 
                "country": "US"
            }
            
            # 执行IP查询
            result = await query_processor._process_ip_query("8.8.8.8")
            
            # 验证API调用
            assert mock_api_provider.get_apis_for_ip_query.called
            assert len(mock_api_provider.get_apis_for_ip_query.return_value) == 2
            
            # 验证结果聚合
            mock_aggregate.assert_called_once()
            assert result == mock_aggregate.return_value
    
    @pytest.mark.asyncio
    async def test_process_url_query(self, query_processor, mock_api_provider):
        """测试URL查询处理"""
        # 模拟结果聚合器
        with patch.object(ResultAggregator, "aggregate_url_results") as mock_aggregate:
            mock_aggregate.return_value = {
                "url": "https://example.com", 
                "threat_score": 0.0, 
                "title": "Example Domain"
            }
            
            # 执行URL查询
            result = await query_processor._process_url_query("https://example.com")
            
            # 验证API调用
            assert mock_api_provider.get_apis_for_url_query.called
            assert len(mock_api_provider.get_apis_for_url_query.return_value) == 2
            
            # 验证结果聚合
            mock_aggregate.assert_called_once()
            assert result == mock_aggregate.return_value
    
    @pytest.mark.asyncio
    async def test_process_hash_query(self, query_processor, mock_api_provider):
        """测试哈希查询处理"""
        # 模拟结果聚合器
        with patch.object(ResultAggregator, "aggregate_hash_results") as mock_aggregate:
            mock_aggregate.return_value = {
                "hash_values": {"md5": "d41d8cd98f00b204e9800998ecf8427e"}, 
                "threat_score": 0.0, 
                "file_type": "text"
            }
            
            # 执行哈希查询
            result = await query_processor._process_hash_query("d41d8cd98f00b204e9800998ecf8427e")
            
            # 验证API调用
            assert mock_api_provider.get_apis_for_hash_query.called
            assert len(mock_api_provider.get_apis_for_hash_query.return_value) == 1
            
            # 验证结果聚合
            mock_aggregate.assert_called_once()
            assert result == mock_aggregate.return_value
    
    def test_determine_hash_type(self, query_processor):
        """测试哈希类型确定"""
        assert query_processor._determine_hash_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
        assert query_processor._determine_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
        assert query_processor._determine_hash_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
        assert query_processor._determine_hash_type("abcdef") == "unknown" 