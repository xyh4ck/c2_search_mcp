"""
日志存储与检索模块
提供日志的存储、搜索和检索功能
"""

import json
import os
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
import sqlite3
import logging


class LogStore:
    """日志存储与检索类"""
    
    def __init__(self, db_path: str = "logs/log_store.db"):
        """
        初始化日志存储器
        
        Args:
            db_path: SQLite数据库文件路径
        """
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # 确保目录存在
        db_dir = os.path.dirname(db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        
        # 初始化数据库
        self._init_db()
    
    def _init_db(self) -> None:
        """初始化数据库表结构"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 创建API请求日志表
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    api_name TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    response_time_ms REAL NOT NULL,
                    error TEXT,
                    service TEXT,
                    extra_data TEXT
                )
                ''')
                
                # 创建查询日志表
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS query_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    query_value TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    duration_ms REAL NOT NULL,
                    error TEXT,
                    service TEXT,
                    extra_data TEXT
                )
                ''')
                
                # 创建索引以提高查询性能
                cursor.execute('CREATE INDEX IF NOT EXISTS api_requests_timestamp ON api_requests (timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS api_requests_api_name ON api_requests (api_name)')
                cursor.execute('CREATE INDEX IF NOT EXISTS query_logs_timestamp ON query_logs (timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS query_logs_query_type ON query_logs (query_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS query_logs_query_value ON query_logs (query_value)')
                
                conn.commit()
                self.logger.info("日志存储数据库初始化完成")
        except sqlite3.Error as e:
            self.logger.error(f"数据库初始化失败: {str(e)}")
    
    def store_api_request(self, 
                         api_name: str, 
                         endpoint: str, 
                         status_code: int, 
                         response_time: float, 
                         error: Optional[str] = None,
                         service: Optional[str] = None,
                         extra_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        存储API请求日志
        
        Args:
            api_name: API名称
            endpoint: 请求端点
            status_code: HTTP状态码
            response_time: 响应时间(毫秒)
            error: 错误信息(如果有)
            service: 服务名称
            extra_data: 其他附加数据
            
        Returns:
            bool: 是否成功存储
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                timestamp = datetime.now().isoformat()
                
                cursor.execute(
                    '''
                    INSERT INTO api_requests 
                    (timestamp, api_name, endpoint, status_code, response_time_ms, error, service, extra_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        timestamp, 
                        api_name, 
                        endpoint, 
                        status_code, 
                        response_time, 
                        error,
                        service,
                        json.dumps(extra_data) if extra_data else None
                    )
                )
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"存储API请求日志失败: {str(e)}")
            return False
    
    def store_query_log(self,
                       query_type: str,
                       query_value: str,
                       client_ip: str,
                       success: bool,
                       duration: float,
                       error: Optional[str] = None,
                       service: Optional[str] = None,
                       extra_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        存储查询日志
        
        Args:
            query_type: 查询类型
            query_value: 查询值
            client_ip: 客户端IP
            success: 是否成功
            duration: 查询耗时(毫秒)
            error: 错误信息(如果有)
            service: 服务名称
            extra_data: 其他附加数据
            
        Returns:
            bool: 是否成功存储
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                timestamp = datetime.now().isoformat()
                
                cursor.execute(
                    '''
                    INSERT INTO query_logs 
                    (timestamp, query_type, query_value, client_ip, success, duration_ms, error, service, extra_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        timestamp, 
                        query_type, 
                        query_value, 
                        client_ip, 
                        1 if success else 0, 
                        duration,
                        error,
                        service,
                        json.dumps(extra_data) if extra_data else None
                    )
                )
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"存储查询日志失败: {str(e)}")
            return False
    
    def search_api_logs(self,
                       start_time: Optional[Union[str, datetime]] = None,
                       end_time: Optional[Union[str, datetime]] = None,
                       api_name: Optional[str] = None,
                       status_code: Optional[int] = None,
                       service: Optional[str] = None,
                       has_error: Optional[bool] = None,
                       limit: int = 100,
                       offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        """
        搜索API请求日志
        
        Args:
            start_time: 开始时间
            end_time: 结束时间
            api_name: API名称
            status_code: HTTP状态码
            service: 服务名称
            has_error: 是否有错误
            limit: 返回记录数量限制
            offset: 分页偏移量
            
        Returns:
            Tuple[List[Dict[str, Any]], int]: 结果列表和总记录数
        """
        try:
            query = "SELECT * FROM api_requests WHERE 1=1"
            count_query = "SELECT COUNT(*) FROM api_requests WHERE 1=1"
            params: List[Union[str, int]] = []
            
            # 构建查询条件
            if start_time:
                if isinstance(start_time, datetime):
                    start_time = start_time.isoformat()
                query += " AND timestamp >= ?"
                count_query += " AND timestamp >= ?"
                params.append(start_time)
            
            if end_time:
                if isinstance(end_time, datetime):
                    end_time = end_time.isoformat()
                query += " AND timestamp <= ?"
                count_query += " AND timestamp <= ?"
                params.append(end_time)
            
            if api_name:
                query += " AND api_name = ?"
                count_query += " AND api_name = ?"
                params.append(api_name)
            
            if status_code:
                query += " AND status_code = ?"
                count_query += " AND status_code = ?"
                params.append(status_code)
            
            if service:
                query += " AND service = ?"
                count_query += " AND service = ?"
                params.append(service)
            
            if has_error is not None:
                if has_error:
                    query += " AND error IS NOT NULL"
                    count_query += " AND error IS NOT NULL"
                else:
                    query += " AND error IS NULL"
                    count_query += " AND error IS NULL"
            
            # 添加排序和分页
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.append(limit)
            params.append(offset)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # 获取总记录数
                count_params = params[:-2] if len(params) >= 2 else params
                cursor.execute(count_query, count_params)
                total_count = cursor.fetchone()[0]
                
                # 获取结果
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                # 构建结果字典
                results = []
                for row in rows:
                    result = dict(row)
                    if result.get('extra_data'):
                        try:
                            result['extra_data'] = json.loads(result['extra_data'])
                        except:
                            pass
                    results.append(result)
                
                return results, total_count
        except sqlite3.Error as e:
            self.logger.error(f"搜索API日志失败: {str(e)}")
            return [], 0
    
    def search_query_logs(self,
                         start_time: Optional[Union[str, datetime]] = None,
                         end_time: Optional[Union[str, datetime]] = None,
                         query_type: Optional[str] = None,
                         query_value: Optional[str] = None,
                         client_ip: Optional[str] = None,
                         success: Optional[bool] = None,
                         service: Optional[str] = None,
                         limit: int = 100,
                         offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        """
        搜索查询日志
        
        Args:
            start_time: 开始时间
            end_time: 结束时间
            query_type: 查询类型
            query_value: 查询值
            client_ip: 客户端IP
            success: 是否成功
            service: 服务名称
            limit: 返回记录数量限制
            offset: 分页偏移量
            
        Returns:
            Tuple[List[Dict[str, Any]], int]: 结果列表和总记录数
        """
        try:
            query = "SELECT * FROM query_logs WHERE 1=1"
            count_query = "SELECT COUNT(*) FROM query_logs WHERE 1=1"
            params: List[Union[str, int]] = []
            
            # 构建查询条件
            if start_time:
                if isinstance(start_time, datetime):
                    start_time = start_time.isoformat()
                query += " AND timestamp >= ?"
                count_query += " AND timestamp >= ?"
                params.append(start_time)
            
            if end_time:
                if isinstance(end_time, datetime):
                    end_time = end_time.isoformat()
                query += " AND timestamp <= ?"
                count_query += " AND timestamp <= ?"
                params.append(end_time)
            
            if query_type:
                query += " AND query_type = ?"
                count_query += " AND query_type = ?"
                params.append(query_type)
            
            if query_value:
                query += " AND query_value LIKE ?"
                count_query += " AND query_value LIKE ?"
                params.append(f"%{query_value}%")
            
            if client_ip:
                query += " AND client_ip = ?"
                count_query += " AND client_ip = ?"
                params.append(client_ip)
            
            if success is not None:
                query += " AND success = ?"
                count_query += " AND success = ?"
                params.append(1 if success else 0)
            
            if service:
                query += " AND service = ?"
                count_query += " AND service = ?"
                params.append(service)
            
            # 添加排序和分页
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.append(limit)
            params.append(offset)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # 获取总记录数
                count_params = params[:-2] if len(params) >= 2 else params
                cursor.execute(count_query, count_params)
                total_count = cursor.fetchone()[0]
                
                # 获取结果
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                # 构建结果字典
                results = []
                for row in rows:
                    result = dict(row)
                    result['success'] = bool(result['success'])
                    if result.get('extra_data'):
                        try:
                            result['extra_data'] = json.loads(result['extra_data'])
                        except:
                            pass
                    results.append(result)
                
                return results, total_count
        except sqlite3.Error as e:
            self.logger.error(f"搜索查询日志失败: {str(e)}")
            return [], 0
    
    def get_api_stats(self, days: int = 30) -> Dict[str, Any]:
        """
        获取API调用统计信息
        
        Args:
            days: 统计天数
            
        Returns:
            Dict[str, Any]: 统计信息
        """
        try:
            start_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 按API名称统计调用次数
                cursor.execute(
                    "SELECT api_name, COUNT(*) as count FROM api_requests WHERE timestamp >= ? GROUP BY api_name",
                    (start_date,)
                )
                api_counts = {row[0]: row[1] for row in cursor.fetchall()}
                
                # 按天统计调用次数
                cursor.execute(
                    "SELECT strftime('%Y-%m-%d', timestamp) as day, COUNT(*) as count FROM api_requests WHERE timestamp >= ? GROUP BY day ORDER BY day",
                    (start_date,)
                )
                daily_counts = {row[0]: row[1] for row in cursor.fetchall()}
                
                # 统计错误率
                cursor.execute(
                    "SELECT COUNT(*) FROM api_requests WHERE timestamp >= ? AND error IS NOT NULL",
                    (start_date,)
                )
                error_count = cursor.fetchone()[0]
                
                cursor.execute(
                    "SELECT COUNT(*) FROM api_requests WHERE timestamp >= ?",
                    (start_date,)
                )
                total_count = cursor.fetchone()[0]
                
                error_rate = error_count / total_count if total_count > 0 else 0
                
                # 统计平均响应时间
                cursor.execute(
                    "SELECT api_name, AVG(response_time_ms) as avg_time FROM api_requests WHERE timestamp >= ? GROUP BY api_name",
                    (start_date,)
                )
                avg_response_times = {row[0]: row[1] for row in cursor.fetchall()}
                
                return {
                    "period_days": days,
                    "total_calls": total_count,
                    "error_count": error_count,
                    "error_rate": error_rate,
                    "api_counts": api_counts,
                    "daily_counts": daily_counts,
                    "avg_response_times": avg_response_times
                }
        except sqlite3.Error as e:
            self.logger.error(f"获取API统计信息失败: {str(e)}")
            return {}
    
    def get_query_stats(self, days: int = 30) -> Dict[str, Any]:
        """
        获取查询统计信息
        
        Args:
            days: 统计天数
            
        Returns:
            Dict[str, Any]: 统计信息
        """
        try:
            start_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 按查询类型统计
                cursor.execute(
                    "SELECT query_type, COUNT(*) as count FROM query_logs WHERE timestamp >= ? GROUP BY query_type",
                    (start_date,)
                )
                type_counts = {row[0]: row[1] for row in cursor.fetchall()}
                
                # 按天统计查询次数
                cursor.execute(
                    "SELECT strftime('%Y-%m-%d', timestamp) as day, COUNT(*) as count FROM query_logs WHERE timestamp >= ? GROUP BY day ORDER BY day",
                    (start_date,)
                )
                daily_counts = {row[0]: row[1] for row in cursor.fetchall()}
                
                # 统计成功率
                cursor.execute(
                    "SELECT COUNT(*) FROM query_logs WHERE timestamp >= ? AND success = 1",
                    (start_date,)
                )
                success_count = cursor.fetchone()[0]
                
                cursor.execute(
                    "SELECT COUNT(*) FROM query_logs WHERE timestamp >= ?",
                    (start_date,)
                )
                total_count = cursor.fetchone()[0]
                
                success_rate = success_count / total_count if total_count > 0 else 0
                
                # 统计平均查询时间
                cursor.execute(
                    "SELECT query_type, AVG(duration_ms) as avg_time FROM query_logs WHERE timestamp >= ? GROUP BY query_type",
                    (start_date,)
                )
                avg_query_times = {row[0]: row[1] for row in cursor.fetchall()}
                
                # 获取最常搜索的值
                cursor.execute(
                    """
                    SELECT query_value, COUNT(*) as count 
                    FROM query_logs 
                    WHERE timestamp >= ? 
                    GROUP BY query_value 
                    ORDER BY count DESC 
                    LIMIT 10
                    """,
                    (start_date,)
                )
                popular_searches = {row[0]: row[1] for row in cursor.fetchall()}
                
                return {
                    "period_days": days,
                    "total_queries": total_count,
                    "success_count": success_count,
                    "success_rate": success_rate,
                    "type_counts": type_counts,
                    "daily_counts": daily_counts,
                    "avg_query_times": avg_query_times,
                    "popular_searches": popular_searches
                }
        except sqlite3.Error as e:
            self.logger.error(f"获取查询统计信息失败: {str(e)}")
            return {} 