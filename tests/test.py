import asyncio
from fastmcp import Client
from src.modules.threat_intel.threatbook import ThreatBookApi
from src.config import ApiEndpointConfig

async def main():
    # 创建 MCP 客户端，FastMCP 会自动推断传输方式
    # client = Client("src/main.py")  # 请确保路径正确

    # async with client:
    #     # 调用 'get_supported_apis' 工具
    #     apis = await client.call_tool("get_supported_apis", {})
    #     print("支持的 API 和查询类型:")
    #     print(apis)

    #     # 调用 'query_threat_intel' 工具，示例查询 IP 地址
    #     query_result = await client.call_tool("query_threat_intel", {
    #         "query_type": "ip",
    #         "query_value": "103.68.181.217"
    #     })
    #     print("查询结果:")
    #     print(query_result)

    # 创建 API 配置
    config = ApiEndpointConfig(
        base_url="https://api.threatbook.cn/v3",
        timeout=60,
        retry_attempts=3,
        rate_limit=50
    )
    
    # 初始化 ThreatBook API
    threatbook = ThreatBookApi(
        api_key="8920560d2a2745caa84041babc4e266554fca59101834264820f1071d15235a5",
        config=config
    )
    
    # 查询IP信息
    data = await threatbook.query_hash('d53eb91918562cd39a56a51ae7ddcbbd6e7585df9332bb706d5d6a9925f07e1c', hash_type='sha256')
    print(data)
    

if __name__ == "__main__":
    asyncio.run(main())
