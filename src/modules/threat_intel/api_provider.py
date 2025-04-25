"""
API提供者
负责初始化和管理威胁情报API实例
"""

from typing import Dict, Any, List, Optional

from src.config import Config
from src.modules.logging.logger import ServiceLogger
from src.modules.threat_intel.virustotal import VirusTotalApi
from src.modules.threat_intel.abuseipdb import AbuseIPDBApi
from src.modules.threat_intel.hybrid_analysis import HybridAnalysisApi
from src.modules.threat_intel.urlscan import URLScanApi
from src.modules.threat_intel.threatfox import ThreatFoxApi
from src.modules.threat_intel.ipinfo import IPinfoApi
from src.modules.threat_intel.shodan import ShodanApi


class APIProvider:
    """API提供者"""
    
    def __init__(self, config: Config):
        """
        初始化API提供者
        
        Args:
            config: 应用配置
        """
        self.config = config
        self.logger = ServiceLogger("api_provider")
        self._apis = {}
        self._initialize_apis()
    
    def _initialize_apis(self):
        """初始化所有API实例"""
        # VirusTotal
        if self.config.api_keys.virustotal:
            self._apis["virustotal"] = VirusTotalApi(
                self.config.api_keys.virustotal,
                self.config.api.virustotal
            )
            self.logger.info("已初始化 VirusTotal API")
        
        # AbuseIPDB
        if self.config.api_keys.abuseipdb:
            self._apis["abuseipdb"] = AbuseIPDBApi(
                self.config.api_keys.abuseipdb,
                self.config.api.abuseipdb
            )
            self.logger.info("已初始化 AbuseIPDB API")
        
        # Hybrid Analysis
        if self.config.api_keys.hybrid_analysis:
            self._apis["hybrid_analysis"] = HybridAnalysisApi(
                self.config.api_keys.hybrid_analysis,
                self.config.api.hybrid_analysis
            )
            self.logger.info("已初始化 Hybrid Analysis API")
        
        # URLScan.io
        if self.config.api_keys.urlscan:
            self._apis["urlscan"] = URLScanApi(
                self.config.api_keys.urlscan,
                self.config.api.urlscan
            )
            self.logger.info("已初始化 URLScan.io API")
        
        # ThreatFox
        if self.config.api_keys.threatfox:
            self._apis["threatfox"] = ThreatFoxApi(
                self.config.api_keys.threatfox,
                self.config.api.threatfox
            )
            self.logger.info("已初始化 ThreatFox API")
        
        # IPinfo
        if self.config.api_keys.ipinfo:
            self._apis["ipinfo"] = IPinfoApi(
                self.config.api_keys.ipinfo,
                self.config.api.ipinfo
            )
            self.logger.info("已初始化 IPinfo API")
        
        # Shodan
        if self.config.api_keys.shodan:
            self._apis["shodan"] = ShodanApi(
                self.config.api_keys.shodan,
                self.config.api.shodan
            )
            self.logger.info("已初始化 Shodan API")
    
    def get_api(self, api_name: str) -> Optional[Any]:
        """
        获取指定的API实例
        
        Args:
            api_name: API名称
            
        Returns:
            Optional[Any]: API实例，如果不存在则返回None
        """
        return self._apis.get(api_name)
    
    def get_all_apis(self) -> Dict[str, Any]:
        """
        获取所有API实例
        
        Returns:
            Dict[str, Any]: API实例字典
        """
        return self._apis
    
    def get_apis_for_ip_query(self) -> List[Any]:
        """
        获取支持IP查询的API列表
        
        Returns:
            List[Any]: API实例列表
        """
        ip_apis = []
        for api_name in ["virustotal", "abuseipdb", "ipinfo", "shodan", "urlscan", "threatfox"]:
            if api_name in self._apis:
                ip_apis.append(self._apis[api_name])
        return ip_apis
    
    def get_apis_for_url_query(self) -> List[Any]:
        """
        获取支持URL查询的API列表
        
        Returns:
            List[Any]: API实例列表
        """
        url_apis = []
        for api_name in ["virustotal", "urlscan", "hybrid_analysis", "threatfox"]:
            if api_name in self._apis:
                url_apis.append(self._apis[api_name])
        return url_apis
    
    def get_apis_for_hash_query(self) -> List[Any]:
        """
        获取支持哈希查询的API列表
        
        Returns:
            List[Any]: API实例列表
        """
        hash_apis = []
        for api_name in ["virustotal", "hybrid_analysis", "threatfox"]:
            if api_name in self._apis:
                hash_apis.append(self._apis[api_name])
        return hash_apis 