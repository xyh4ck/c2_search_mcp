import asyncio
from fastmcp import Client

async def main():
    # 创建 MCP 客户端，FastMCP 会自动推断传输方式
    client = Client("src/main.py")  # 请确保路径正确

    async with client:
        # 调用 'get_supported_apis' 工具
        apis = await client.call_tool("get_supported_apis", {})
        print("支持的 API 和查询类型:")
        print(apis)

        # 调用 'query_threat_intel' 工具，示例查询 IP 地址
        query_result = await client.call_tool("query_threat_intel", {
            "query_type": "ip",
            "query_value": "8.8.8.8"
        })
        print("查询结果:")
        print(query_result)

if __name__ == "__main__":
    asyncio.run(main())
