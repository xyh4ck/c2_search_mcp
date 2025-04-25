"""
基于FastMCP的威胁情报查询服务
"""
from fastmcp import FastMCP
from typing import Dict, Any, List
from src.modules.query_processor.processor import QueryProcessor
from src.config import load_config

# 创建FastMCP实例
mcp = FastMCP("威胁情报查询服务 🚀")

# 加载配置
config = load_config("config.yaml")

# 创建查询处理器
processor = QueryProcessor(config)

@mcp.tool()
async def query_threat_intel(query_type: str, query_value: str) -> Dict[str, Any]:
    """
    查询威胁情报信息
    
    Args:
        query_type: 查询类型 (ip/url/hash)
        query_value: 查询值
    
    Returns:
        Dict[str, Any]: 查询结果
    """
    result = await processor.process_query(query_type, query_value, "localhost")
    return result

@mcp.tool()
async def get_supported_apis() -> Dict[str, List[str]]:
    """
    获取支持的API和查询类型
    
    Returns:
        Dict[str, List[str]]: 支持的API和查询类型
    """
    return {
        "supported_query_types": ["ip", "url", "hash"],
        "integrated_apis": [
            "virustotal",
            "abuseipdb",
            "hybrid_analysis",
            "urlscan",
            "threatfox",
            "ipinfo",
            "shodan"
        ]
    }

if __name__ == "__main__":
    mcp.run() 