"""
查询参数验证模块
"""

import re
import ipaddress
from typing import Tuple, Union

import validators


class QueryValidator:
    """查询参数验证器"""
    
    @staticmethod
    def validate_ip(ip_str: str) -> Tuple[bool, str]:
        """
        验证IP地址格式
        
        Args:
            ip_str: IP地址字符串
            
        Returns:
            Tuple[bool, str]: (是否有效, 错误信息)
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return True, ""
        except ValueError:
            return False, f"无效的IP地址格式: {ip_str}"
    
    @staticmethod
    def validate_url(url_str: str) -> Tuple[bool, str]:
        """
        验证URL格式
        
        Args:
            url_str: URL字符串
            
        Returns:
            Tuple[bool, str]: (是否有效, 错误信息)
        """
        if validators.url(url_str):
            return True, ""
        else:
            return False, f"无效的URL格式: {url_str}"
    
    @staticmethod
    def validate_hash(hash_str: str) -> Tuple[bool, str, str]:
        """
        验证哈希值格式
        
        Args:
            hash_str: 哈希字符串
            
        Returns:
            Tuple[bool, str, str]: (是否有效, 哈希类型, 错误信息)
        """
        hash_str = hash_str.lower()
        
        # MD5: 32个十六进制字符
        if re.match(r"^[a-f0-9]{32}$", hash_str):
            return True, "md5", ""
        
        # SHA-1: 40个十六进制字符
        elif re.match(r"^[a-f0-9]{40}$", hash_str):
            return True, "sha1", ""
        
        # SHA-256: 64个十六进制字符
        elif re.match(r"^[a-f0-9]{64}$", hash_str):
            return True, "sha256", ""
        
        else:
            return False, "", f"无效的哈希格式: {hash_str}，支持MD5、SHA1、SHA256"
    
    @classmethod
    def validate_query(cls, query_type: str, query_value: str) -> Tuple[bool, Union[str, None]]:
        """
        验证查询参数
        
        Args:
            query_type: 查询类型 (ip, url, hash)
            query_value: 查询值
            
        Returns:
            Tuple[bool, Union[str, None]]: (是否有效, 错误信息)
        """
        if not query_value:
            return False, "查询值不能为空"
        
        if query_type == "ip":
            valid, error = cls.validate_ip(query_value)
            return valid, error
        
        elif query_type == "url":
            valid, error = cls.validate_url(query_value)
            return valid, error
        
        elif query_type == "hash":
            valid, hash_type, error = cls.validate_hash(query_value)
            return valid, error
        
        else:
            return False, f"不支持的查询类型: {query_type}" 