"""
CVE-Search响应格式化器
"""

from typing import Dict, Any, List, Optional, Union

class CVESearchFormatter:
    """CVE-Search响应格式化器"""
    
    @staticmethod
    def format_response(data: Dict[str, Any], query_type: str) -> Dict[str, Any]:
        """
        根据查询类型格式化CVE-Search响应
        
        Args:
            data: 原始响应数据
            query_type: 查询类型 ('vendors', 'vendor_products', 'cve', 'latest', 'db_status')
            
        Returns:
            Dict[str, Any]: 格式化后的响应
        """
        if data.get("status") == "error":
            return {
                "status": "error",
                "message": data.get("error", "未知错误"),
                "execution_time_ms": data.get("execution_time_ms", 0)
            }
        
        # 根据查询类型调用相应的格式化方法
        if query_type == "vendors":
            formatted_data = CVESearchFormatter._format_vendors(data.get("data", []))
        elif query_type == "vendor_products":
            formatted_data = CVESearchFormatter._format_vendor_products(data.get("data", []))
        elif query_type == "vendor_product_vulnerabilities":
            formatted_data = CVESearchFormatter._format_vulnerabilities(data.get("data", []))
        elif query_type == "cve":
            formatted_data = CVESearchFormatter._format_cve_details(data.get("data", {}))
        elif query_type == "latest":
            formatted_data = CVESearchFormatter._format_latest_vulnerabilities(data.get("data", []))
        elif query_type == "db_status":
            formatted_data = CVESearchFormatter._format_db_status(data.get("data", {}))
        else:
            formatted_data = data.get("data", {})
        
        return {
            "status": "success",
            "data": formatted_data,
            "execution_time_ms": data.get("execution_time_ms", 0)
        }
    
    @staticmethod
    def _format_vendors(vendors_data: Any) -> Dict[str, Any]:
        """
        格式化供应商列表
        
        Args:
            vendors_data: 供应商数据
            
        Returns:
            Dict[str, Any]: 格式化后的供应商数据
        """
        if isinstance(vendors_data, list):
            return {
                "total_vendors": len(vendors_data),
                "vendors": vendors_data
            }
        return {
            "total_vendors": 0,
            "vendors": []
        }
    
    @staticmethod
    def _format_vendor_products(products_data: Any) -> Dict[str, Any]:
        """
        格式化供应商产品列表
        
        Args:
            products_data: 产品数据
            
        Returns:
            Dict[str, Any]: 格式化后的产品数据
        """
        if isinstance(products_data, list):
            return {
                "total_products": len(products_data),
                "products": products_data
            }
        return {
            "total_products": 0,
            "products": []
        }
    
    @staticmethod
    def _format_vulnerabilities(vulnerabilities_data: Any) -> Dict[str, Any]:
        """
        格式化漏洞列表
        
        Args:
            vulnerabilities_data: 漏洞数据
            
        Returns:
            Dict[str, Any]: 格式化后的漏洞数据
        """
        if not isinstance(vulnerabilities_data, list):
            return {
                "total_vulnerabilities": 0,
                "vulnerabilities": []
            }
        
        formatted_vulnerabilities = []
        for vuln in vulnerabilities_data:
            formatted_vuln = {
                "id": vuln.get("id", ""),
                "cvss": vuln.get("cvss", 0),
                "summary": vuln.get("summary", ""),
                "published": vuln.get("Published", ""),
                "last_modified": vuln.get("Modified", ""),
                "cwe": vuln.get("cwe", ""),
                "references": vuln.get("references", [])
            }
            formatted_vulnerabilities.append(formatted_vuln)
        
        return {
            "total_vulnerabilities": len(formatted_vulnerabilities),
            "vulnerabilities": formatted_vulnerabilities
        }
    
    @staticmethod
    def _format_cve_details(cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        格式化CVE详细信息
        
        Args:
            cve_data: CVE数据
            
        Returns:
            Dict[str, Any]: 格式化后的CVE数据
        """
        if not cve_data:
            return {}
        
        # 提取关键信息
        formatted_cve = {
            "id": cve_data.get("id", ""),
            "cvss": cve_data.get("cvss", 0),
            "cvss3": cve_data.get("cvss3", 0),
            "summary": cve_data.get("summary", ""),
            "published": cve_data.get("Published", ""),
            "last_modified": cve_data.get("Modified", ""),
            "cwe": cve_data.get("cwe", ""),
            "references": cve_data.get("references", []),
            "vulnerable_configuration": cve_data.get("vulnerable_configuration", []),
            "vulnerable_configuration_cpe_2_2": cve_data.get("vulnerable_configuration_cpe_2_2", []),
            "capec": CVESearchFormatter._format_capec(cve_data.get("capec", [])),
            "risk_score": CVESearchFormatter._calculate_risk_score(cve_data)
        }
        
        return formatted_cve
    
    @staticmethod
    def _format_capec(capec_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        格式化CAPEC数据
        
        Args:
            capec_data: CAPEC数据
            
        Returns:
            List[Dict[str, Any]]: 格式化后的CAPEC数据
        """
        formatted_capec = []
        for capec in capec_data:
            formatted_capec.append({
                "id": capec.get("id", ""),
                "name": capec.get("name", ""),
                "summary": capec.get("summary", ""),
                "prerequisites": capec.get("prerequisites", ""),
                "solutions": capec.get("solutions", "")
            })
        return formatted_capec
    
    @staticmethod
    def _format_latest_vulnerabilities(vulnerabilities_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        格式化最新漏洞列表
        
        Args:
            vulnerabilities_data: 漏洞数据
            
        Returns:
            Dict[str, Any]: 格式化后的漏洞数据
        """
        if not isinstance(vulnerabilities_data, list):
            return {
                "total_vulnerabilities": 0,
                "vulnerabilities": []
            }
        
        return CVESearchFormatter._format_vulnerabilities(vulnerabilities_data)
    
    @staticmethod
    def _format_db_status(db_status_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        格式化数据库状态信息
        
        Args:
            db_status_data: 数据库状态数据
            
        Returns:
            Dict[str, Any]: 格式化后的数据库状态
        """
        if not db_status_data:
            return {}
        
        formatted_status = {}
        for db_name, db_info in db_status_data.items():
            if isinstance(db_info, dict):
                formatted_status[db_name] = {
                    "last_update": db_info.get("last-modified", "未知"),
                    "size": db_info.get("size", 0),
                    "format": db_info.get("format", "未知")
                }
        
        return formatted_status
    
    @staticmethod
    def _calculate_risk_score(cve_data: Dict[str, Any]) -> float:
        """
        计算风险评分
        
        Args:
            cve_data: CVE数据
            
        Returns:
            float: 风险评分
        """
        # 基于CVSS计算风险评分
        cvss = cve_data.get("cvss", 0)
        cvss3 = cve_data.get("cvss3", 0)
        
        # 优先使用CVSS3，如果可用
        base_score = cvss3 if cvss3 else cvss
        
        # 加权因素：发布时间（越新权重越高）
        # 这里可以根据需要添加更多因素进行评分调整
        
        return float(base_score) 