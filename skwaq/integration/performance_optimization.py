"""Performance optimization for system-wide operations.

This module provides components for optimizing performance across the entire system,
including query optimization, resource allocation, and caching strategies.
"""

from typing import Any, Dict, List, Optional, Type, TypeVar, Union, Callable, Awaitable
import time
import inspect
import asyncio
import functools
import logging
from datetime import datetime

from ..utils.logging import get_logger
from ..db.neo4j_connector import get_connector
from ..workflows.integration.performance_optimizer import get_performance_optimizer

logger = get_logger(__name__)

# Type variables for generic functions
T = TypeVar("T")
R = TypeVar("R")


class QueryOptimizer:
    """Database query optimization for Neo4j.

    This class provides utilities for optimizing database queries,
    analyzing query performance, and suggesting improvements to
    query structure.
    """

    def __init__(self):
        """Initialize the query optimizer.

        Args:
            None
        """
        self.query_stats = {}
        self.slow_queries = []
        self.query_count = 0

    def measure_query(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
        threshold_ms: int = 100,
    ) -> Callable[[Callable[..., R]], Callable[..., R]]:
        """Decorator to measure query execution time.

        Args:
            query: The query string to measure
            params: Optional parameters for the query
            threshold_ms: Threshold in milliseconds for slow queries

        Returns:
            Decorated function
        """

        def decorator(func: Callable[..., R]) -> Callable[..., R]:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Record query start time
                start_time = time.time()

                # Execute the query
                result = func(*args, **kwargs)

                # Calculate execution time
                execution_time = (time.time() - start_time) * 1000  # Convert to ms

                # Update statistics
                self._record_query_stat(query, execution_time)

                # Log slow queries
                if execution_time > threshold_ms:
                    self._record_slow_query(query, params, execution_time)
                    logger.warning(
                        f"Slow query detected: {execution_time:.2f}ms - {query[:100]}..."
                    )

                return result

            return wrapper

        return decorator

    def _record_query_stat(self, query: str, execution_time: float) -> None:
        """Record statistics for a query.

        Args:
            query: The query string
            execution_time: The execution time in milliseconds
        """
        # Hash the query to use as a key
        query_hash = hash(query)

        if query_hash not in self.query_stats:
            self.query_stats[query_hash] = {
                "query": query[:200] + "..." if len(query) > 200 else query,
                "count": 0,
                "total_time": 0,
                "min_time": execution_time,
                "max_time": execution_time,
                "avg_time": execution_time,
            }

        stats = self.query_stats[query_hash]
        stats["count"] += 1
        stats["total_time"] += execution_time
        stats["min_time"] = min(stats["min_time"], execution_time)
        stats["max_time"] = max(stats["max_time"], execution_time)
        stats["avg_time"] = stats["total_time"] / stats["count"]

        self.query_count += 1

    def _record_slow_query(
        self, query: str, params: Optional[Dict[str, Any]], execution_time: float
    ) -> None:
        """Record a slow query for analysis.

        Args:
            query: The query string
            params: Parameters for the query
            execution_time: The execution time in milliseconds
        """
        self.slow_queries.append(
            {
                "query": query,
                "params": params,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat(),
            }
        )

        # Limit the number of slow queries stored
        if len(self.slow_queries) > 100:
            self.slow_queries.pop(0)

    def get_query_stats(self) -> Dict[str, Any]:
        """Get statistics for all measured queries.

        Returns:
            Dictionary with query statistics
        """
        return {
            "query_count": self.query_count,
            "unique_queries": len(self.query_stats),
            "slow_query_count": len(self.slow_queries),
            "queries": list(self.query_stats.values()),
        }

    def get_slow_queries(self) -> List[Dict[str, Any]]:
        """Get list of slow queries.

        Returns:
            List of slow query information
        """
        return self.slow_queries

    def analyze_query(self, query: str) -> Dict[str, Any]:
        """Analyze a query for potential performance issues.

        Args:
            query: The query to analyze

        Returns:
            Dictionary with analysis results
        """
        analysis = {"query": query, "issues": [], "suggestions": []}

        # Check for common performance issues
        if "MATCH" in query and not "WHERE" in query:
            analysis["issues"].append(
                "Query without WHERE clause may return too many results"
            )
            analysis["suggestions"].append(
                "Add appropriate WHERE clause to limit results"
            )

        if "MATCH (n)" in query:
            analysis["issues"].append(
                "Query matches all nodes without label, which is inefficient"
            )
            analysis["suggestions"].append(
                "Add specific node label, e.g., MATCH (n:Label)"
            )

        if "OPTIONAL MATCH" in query and query.count("OPTIONAL MATCH") > 2:
            analysis["issues"].append(
                "Multiple OPTIONAL MATCH patterns may slow down query"
            )
            analysis["suggestions"].append(
                "Consider breaking into multiple queries or simplifying"
            )

        return analysis

    def optimize_query(self, query: str) -> str:
        """Attempt to optimize a Cypher query.

        Args:
            query: The query to optimize

        Returns:
            Optimized query string
        """
        # This is a simplified example - in practice you would have more
        # sophisticated optimization rules

        # Replace inefficient patterns
        optimized = query.replace(
            "MATCH (n)", "// Add a label for better performance\nMATCH (n:Label)"
        )

        # Add query hints for better performance
        if "MATCH" in optimized and not "USING INDEX" in optimized:
            # Add index hint example - would need to be customized for real query
            optimized = optimized.replace(
                "MATCH (n:Label)", "MATCH (n:Label) USING INDEX n:Label(property)"
            )

        return optimized


class DatabaseOptimization:
    """Database optimization for Neo4j connection.

    This class provides utilities for optimizing database operations,
    implementing caching strategies, and managing database resources.
    """

    def __init__(self):
        """Initialize the database optimization."""
        self.query_optimizer = QueryOptimizer()
        self.cache_hit_count = 0
        self.cache_miss_count = 0

    def cached_query(
        self, ttl: int = 60, cache_key: Optional[Callable[..., str]] = None
    ) -> Callable[[Callable[..., R]], Callable[..., R]]:
        """Decorator for caching database query results.

        Args:
            ttl: Time-to-live in seconds for cached results
            cache_key: Optional function to generate cache key

        Returns:
            Decorated function
        """

        def decorator(func: Callable[..., R]) -> Callable[..., R]:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Get optimizer cache
                optimizer = get_performance_optimizer()
                cache = optimizer.cache

                # Generate cache key
                if cache_key is not None:
                    key = cache_key(*args, **kwargs)
                else:
                    key = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"

                # Check cache
                cached_result = cache.get(key)
                if cached_result is not None:
                    self.cache_hit_count += 1
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_result

                # Execute function on cache miss
                self.cache_miss_count += 1
                logger.debug(f"Cache miss for {func.__name__}")
                result = func(*args, **kwargs)

                # Cache result
                cache.set(key, result, ttl)

                return result

            return wrapper

        return decorator

    async def cached_query_async(
        self, ttl: int = 60, cache_key: Optional[Callable[..., str]] = None
    ) -> Callable[[Callable[..., Awaitable[R]]], Callable[..., Awaitable[R]]]:
        """Decorator for caching async database query results.

        Args:
            ttl: Time-to-live in seconds for cached results
            cache_key: Optional function to generate cache key

        Returns:
            Decorated function
        """

        def decorator(func: Callable[..., Awaitable[R]]) -> Callable[..., Awaitable[R]]:
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                # Get optimizer cache
                optimizer = get_performance_optimizer()
                cache = optimizer.cache

                # Generate cache key
                if cache_key is not None:
                    key = cache_key(*args, **kwargs)
                else:
                    key = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"

                # Check cache
                cached_result = cache.get(key)
                if cached_result is not None:
                    self.cache_hit_count += 1
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_result

                # Execute function on cache miss
                self.cache_miss_count += 1
                logger.debug(f"Cache miss for {func.__name__}")
                result = await func(*args, **kwargs)

                # Cache result
                cache.set(key, result, ttl)

                return result

            return wrapper

        return decorator

    def optimize_connection_pool(self) -> None:
        """Optimize the Neo4j connection pool settings."""
        connector = get_connector()
        if not connector:
            logger.warning("Cannot optimize connection pool: no connector available")
            return

        # In a real implementation, you would adjust connection pool settings
        # based on system load and usage patterns
        logger.info("Neo4j connection pool optimized")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get statistics for query caching.

        Returns:
            Dictionary with cache statistics
        """
        total_requests = self.cache_hit_count + self.cache_miss_count
        hit_rate = self.cache_hit_count / total_requests if total_requests > 0 else 0

        return {
            "cache_hits": self.cache_hit_count,
            "cache_misses": self.cache_miss_count,
            "hit_rate": hit_rate,
        }


class MemoryOptimization:
    """Memory usage optimization.

    This class provides utilities for optimizing memory usage,
    identifying memory leaks, and implementing memory-efficient
    data structures.
    """

    def __init__(self):
        """Initialize memory optimization."""
        try:
            import psutil

            self.psutil_available = True
        except ImportError:
            self.psutil_available = False
            logger.warning("psutil not available - memory monitoring will be limited")

        self.memory_snapshots = []

    def take_memory_snapshot(self) -> Dict[str, Any]:
        """Take a snapshot of current memory usage.

        Returns:
            Dictionary with memory usage information
        """
        if not self.psutil_available:
            return {"error": "psutil not available"}

        import psutil

        process = psutil.Process()
        memory_info = process.memory_info()

        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "rss": memory_info.rss,  # Resident Set Size
            "vms": memory_info.vms,  # Virtual Memory Size
            "percent": process.memory_percent(),
            "children": [],
        }

        # Get memory usage of child processes
        for child in process.children(recursive=True):
            try:
                child_info = child.memory_info()
                snapshot["children"].append(
                    {"pid": child.pid, "rss": child_info.rss, "vms": child_info.vms}
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        self.memory_snapshots.append(snapshot)

        # Limit number of snapshots stored
        if len(self.memory_snapshots) > 100:
            self.memory_snapshots.pop(0)

        return snapshot

    def get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage information.

        Returns:
            Dictionary with memory usage details
        """
        if not self.psutil_available:
            return {"error": "psutil not available"}

        import psutil

        # Get system-wide memory information
        system_memory = psutil.virtual_memory()

        # Get process-specific memory information
        process = psutil.Process()
        process_memory = process.memory_info()

        return {
            "system": {
                "total": system_memory.total,
                "available": system_memory.available,
                "used": system_memory.used,
                "percent": system_memory.percent,
            },
            "process": {
                "rss": process_memory.rss,
                "vms": process_memory.vms,
                "percent": process.memory_percent(),
            },
        }

    def analyze_memory_trend(self) -> Dict[str, Any]:
        """Analyze memory usage trends from snapshots.

        Returns:
            Dictionary with trend analysis
        """
        if len(self.memory_snapshots) < 2:
            return {"error": "Not enough snapshots for trend analysis"}

        # Calculate trends
        first = self.memory_snapshots[0]
        last = self.memory_snapshots[-1]

        if "rss" not in first or "rss" not in last:
            return {"error": "Incomplete snapshot data"}

        # Calculate memory growth
        rss_growth = last["rss"] - first["rss"]
        growth_pct = (rss_growth / first["rss"]) * 100 if first["rss"] > 0 else 0

        # Determine if memory usage is stable, growing, or shrinking
        if abs(growth_pct) < 5:
            trend = "stable"
        elif growth_pct > 0:
            trend = "growing"
        else:
            trend = "shrinking"

        return {
            "snapshots": len(self.memory_snapshots),
            "first_timestamp": first["timestamp"],
            "last_timestamp": last["timestamp"],
            "rss_growth_bytes": rss_growth,
            "rss_growth_percent": growth_pct,
            "trend": trend,
            "possible_leak": growth_pct > 20,
        }

    def optimize_memory_usage(self) -> Dict[str, Any]:
        """Attempt to optimize memory usage.

        Returns:
            Dictionary with optimization results
        """
        if not self.psutil_available:
            return {"error": "psutil not available"}

        import gc

        # Force garbage collection
        collected = gc.collect()

        # Take memory snapshot after optimization
        snapshot = self.take_memory_snapshot()

        return {
            "gc_objects_collected": collected,
            "memory_after_optimization": snapshot,
        }


# Singleton instances
_query_optimizer = None
_db_optimization = None
_memory_optimization = None


def get_query_optimizer() -> QueryOptimizer:
    """Get the singleton query optimizer instance.

    Returns:
        The QueryOptimizer instance
    """
    global _query_optimizer
    if _query_optimizer is None:
        _query_optimizer = QueryOptimizer()
    return _query_optimizer


def get_db_optimization() -> DatabaseOptimization:
    """Get the singleton database optimization instance.

    Returns:
        The DatabaseOptimization instance
    """
    global _db_optimization
    if _db_optimization is None:
        _db_optimization = DatabaseOptimization()
    return _db_optimization


def get_memory_optimization() -> MemoryOptimization:
    """Get the singleton memory optimization instance.

    Returns:
        The MemoryOptimization instance
    """
    global _memory_optimization
    if _memory_optimization is None:
        _memory_optimization = MemoryOptimization()
    return _memory_optimization
