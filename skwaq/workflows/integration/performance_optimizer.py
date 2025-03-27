"""Performance optimization for workflow execution.

This module provides components for optimizing workflow performance through
caching, parallel execution, and resource usage optimization.
"""

from typing import Any, Dict, List, Optional, Set, Type, TypeVar, Union, Callable, Awaitable, AsyncGenerator
import asyncio
import json
import time
import functools
import hashlib
from datetime import datetime, timedelta

from ...utils.logging import get_logger
from ...db.neo4j_connector import get_connector
from ..base import Workflow

logger = get_logger(__name__)

# Type variable for generic function types
T = TypeVar('T')
R = TypeVar('R')


class CacheEntry:
    """Represents a cached result with metadata.
    
    This class stores a cached result along with metadata such as
    creation time, TTL, and cache key for better cache management.
    """
    
    def __init__(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ):
        """Initialize a cache entry.
        
        Args:
            key: The cache key
            value: The cached value
            ttl: Optional time-to-live in seconds
        """
        self.key = key
        self.value = value
        self.created_at = datetime.now()
        self.ttl = ttl
        
    def is_expired(self) -> bool:
        """Check if the cache entry has expired.
        
        Returns:
            True if the entry has expired, False otherwise
        """
        if self.ttl is None:
            return False
            
        expiry_time = self.created_at + timedelta(seconds=self.ttl)
        return datetime.now() > expiry_time


class WorkflowCache:
    """Caching system for workflow operations.
    
    This class provides functionality for caching expensive operations
    in workflows to improve performance on repeated executions.
    """
    
    def __init__(self, max_size: int = 1000):
        """Initialize the workflow cache.
        
        Args:
            max_size: Maximum number of entries to store in the cache
        """
        self._cache: Dict[str, CacheEntry] = {}
        self._max_size = max_size
        self._hits = 0
        self._misses = 0
        
    def clear(self) -> None:
        """Clear all entries from the cache."""
        self._cache.clear()
        
    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from the cache.
        
        Args:
            key: The cache key
            default: Default value to return if key doesn't exist or is expired
            
        Returns:
            The cached value or default
        """
        if key not in self._cache:
            self._misses += 1
            return default
            
        entry = self._cache[key]
        if entry.is_expired():
            self._misses += 1
            del self._cache[key]
            return default
            
        self._hits += 1
        return entry.value
        
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value in the cache.
        
        Args:
            key: The cache key
            value: The value to cache
            ttl: Optional time-to-live in seconds
        """
        # Ensure we don't exceed max size
        if len(self._cache) >= self._max_size and key not in self._cache:
            # Remove the oldest entry
            oldest_key = min(
                self._cache.keys(),
                key=lambda k: self._cache[k].created_at
            )
            del self._cache[oldest_key]
            
        # Add new entry
        self._cache[key] = CacheEntry(key, value, ttl)
        
    def invalidate(self, key: str) -> None:
        """Invalidate a specific cache entry.
        
        Args:
            key: The cache key to invalidate
        """
        if key in self._cache:
            del self._cache[key]
            
    def invalidate_pattern(self, pattern: str) -> None:
        """Invalidate cache entries matching a pattern.
        
        Args:
            pattern: The pattern to match against cache keys
        """
        keys_to_remove = [
            key for key in self._cache.keys() 
            if pattern in key
        ]
        
        for key in keys_to_remove:
            del self._cache[key]
            
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        total_requests = self._hits + self._misses
        hit_rate = self._hits / total_requests if total_requests > 0 else 0
        
        return {
            "size": len(self._cache),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": hit_rate,
            "expired_entries": sum(1 for entry in self._cache.values() if entry.is_expired())
        }


class PerformanceOptimizer:
    """Performance optimization for workflow execution.
    
    This class provides functionality for optimizing workflow performance
    through caching, parallel execution, and resource usage management.
    """
    
    def __init__(self):
        """Initialize the performance optimizer."""
        self.cache = WorkflowCache()
        self._active_tasks: Dict[str, asyncio.Task] = {}
        self._semaphores: Dict[str, asyncio.Semaphore] = {}
        
    def cached(
        self,
        ttl: Optional[int] = 3600,
        key_fn: Optional[Callable[..., str]] = None
    ) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
        """Decorator for caching async function results.
        
        Args:
            ttl: Optional time-to-live in seconds
            key_fn: Optional function to generate a cache key
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> T:
                # Generate cache key
                if key_fn is not None:
                    cache_key = key_fn(*args, **kwargs)
                else:
                    # Default key generation using function name and arguments
                    key_parts = [func.__name__]
                    for arg in args:
                        try:
                            key_parts.append(str(hash(arg)))
                        except TypeError:
                            key_parts.append(str(id(arg)))
                    
                    for k, v in sorted(kwargs.items()):
                        key_parts.append(f"{k}=")
                        try:
                            key_parts.append(str(hash(v)))
                        except TypeError:
                            key_parts.append(str(id(v)))
                    
                    cache_key = hashlib.md5("".join(key_parts).encode()).hexdigest()
                
                # Check if result is in cache
                cached_result = self.cache.get(cache_key)
                if cached_result is not None:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_result
                
                # Execute function and cache result
                logger.debug(f"Cache miss for {func.__name__}")
                result = await func(*args, **kwargs)
                self.cache.set(cache_key, result, ttl)
                
                return result
            
            return wrapper
        
        return decorator
    
    def parallel(
        self,
        max_concurrency: int = 5,
        group: str = "default"
    ) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
        """Decorator for executing functions with controlled concurrency.
        
        Args:
            max_concurrency: Maximum number of concurrent executions
            group: Resource group for concurrency control
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> T:
                # Get or create semaphore for this group
                if group not in self._semaphores:
                    self._semaphores[group] = asyncio.Semaphore(max_concurrency)
                semaphore = self._semaphores[group]
                
                # Execute with concurrency control
                async with semaphore:
                    result = await func(*args, **kwargs)
                    return result
            
            return wrapper
        
        return decorator
    
    async def execute_in_parallel(
        self,
        tasks: List[Callable[[], Awaitable[T]]],
        max_concurrency: int = 5
    ) -> List[T]:
        """Execute multiple tasks in parallel with controlled concurrency.
        
        Args:
            tasks: List of task functions to execute
            max_concurrency: Maximum number of concurrent executions
            
        Returns:
            List of task results
        """
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def execute_with_semaphore(task: Callable[[], Awaitable[T]]) -> T:
            async with semaphore:
                return await task()
        
        # Create and gather tasks
        coroutines = [execute_with_semaphore(task) for task in tasks]
        results = await asyncio.gather(*coroutines, return_exceptions=True)
        
        # Handle exceptions
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Task {i} failed with error: {result}")
                
        return results
    
    def monitor_execution_time(
        self,
        threshold_ms: int = 500
    ) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
        """Decorator for monitoring execution time of async functions.
        
        Args:
            threshold_ms: Threshold in milliseconds for logging slow executions
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> T:
                start_time = time.time()
                
                try:
                    result = await func(*args, **kwargs)
                finally:
                    execution_time = (time.time() - start_time) * 1000  # Convert to ms
                    
                    if execution_time > threshold_ms:
                        logger.warning(
                            f"Slow execution: {func.__name__} took {execution_time:.2f}ms "
                            f"(threshold: {threshold_ms}ms)"
                        )
                        
                        # Record slow operations for analysis
                        if hasattr(func, "__module__") and hasattr(func, "__qualname__"):
                            self._record_slow_operation(
                                f"{func.__module__}.{func.__qualname__}",
                                execution_time,
                                threshold_ms
                            )
                
                return result
            
            return wrapper
        
        return decorator
    
    def _record_slow_operation(
        self, function_name: str, execution_time: float, threshold: int
    ) -> None:
        """Record a slow operation for later analysis.
        
        Args:
            function_name: The name of the slow function
            execution_time: The execution time in milliseconds
            threshold: The threshold that was exceeded
        """
        # Get Neo4j connector
        connector = get_connector()
        if not connector:
            logger.error("Cannot record slow operation: database connection failed")
            return
            
        # Record the slow operation
        props = {
            "function_name": function_name,
            "execution_time_ms": execution_time,
            "threshold_ms": threshold,
            "timestamp": datetime.now().isoformat(),
        }
        
        connector.create_node("SlowOperation", props)


class ResourceManager:
    """Manages resource allocation for workflows.
    
    This class provides functionality for managing resources like memory,
    CPU, and connection pools to optimize workflow performance.
    """
    
    def __init__(
        self,
        max_memory_mb: int = 1024,
        max_connections: int = 100,
        max_concurrent_tasks: int = 20
    ):
        """Initialize the resource manager.
        
        Args:
            max_memory_mb: Maximum memory usage in MB
            max_connections: Maximum number of concurrent connections
            max_concurrent_tasks: Maximum number of concurrent tasks
        """
        self.max_memory_mb = max_memory_mb
        self.max_connections = max_connections
        self.max_concurrent_tasks = max_concurrent_tasks
        
        self._task_semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self._connection_semaphore = asyncio.Semaphore(max_connections)
        self._active_tasks: Dict[str, asyncio.Task] = {}
        
    async def execute_with_resource_control(
        self,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        **kwargs: Any
    ) -> T:
        """Execute a function with resource control.
        
        Args:
            func: The function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            The function result
        """
        # Acquire task semaphore
        async with self._task_semaphore:
            # Execute the function
            return await func(*args, **kwargs)
    
    async def with_connection(
        self,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        **kwargs: Any
    ) -> T:
        """Execute a function with connection control.
        
        Args:
            func: The function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            The function result
        """
        # Acquire connection semaphore
        async with self._connection_semaphore:
            # Execute the function
            return await func(*args, **kwargs)
    
    def register_task(self, task_id: str, task: asyncio.Task) -> None:
        """Register an active task for tracking.
        
        Args:
            task_id: The task identifier
            task: The asyncio Task object
        """
        self._active_tasks[task_id] = task
        
        # Set up callback for cleanup when task completes
        task.add_done_callback(
            lambda _: self._cleanup_task(task_id)
        )
    
    def _cleanup_task(self, task_id: str) -> None:
        """Clean up a completed task.
        
        Args:
            task_id: The task identifier
        """
        if task_id in self._active_tasks:
            del self._active_tasks[task_id]
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task.
        
        Args:
            task_id: The task identifier
            
        Returns:
            True if the task was cancelled, False if not found
        """
        if task_id in self._active_tasks:
            task = self._active_tasks[task_id]
            if not task.done():
                task.cancel()
            return True
        return False
    
    def get_active_task_count(self) -> int:
        """Get the number of active tasks.
        
        Returns:
            The number of active tasks
        """
        return len(self._active_tasks)
    
    def get_resource_usage(self) -> Dict[str, Any]:
        """Get current resource usage information.
        
        Returns:
            Dictionary with resource usage metrics
        """
        try:
            import psutil
            
            process = psutil.Process()
            memory_info = process.memory_info()
            
            return {
                "memory_usage_mb": memory_info.rss / (1024 * 1024),
                "memory_percent": process.memory_percent(),
                "cpu_percent": process.cpu_percent(),
                "active_tasks": len(self._active_tasks),
                "available_task_slots": self._task_semaphore._value,
                "available_connection_slots": self._connection_semaphore._value
            }
        except ImportError:
            return {
                "active_tasks": len(self._active_tasks),
                "available_task_slots": self._task_semaphore._value,
                "available_connection_slots": self._connection_semaphore._value,
                "note": "Install psutil for detailed memory and CPU metrics"
            }


# Singleton instances
_performance_optimizer = None
_resource_manager = None


def get_performance_optimizer() -> PerformanceOptimizer:
    """Get the singleton performance optimizer instance.
    
    Returns:
        The PerformanceOptimizer instance
    """
    global _performance_optimizer
    if _performance_optimizer is None:
        _performance_optimizer = PerformanceOptimizer()
    return _performance_optimizer


def get_resource_manager() -> ResourceManager:
    """Get the singleton resource manager instance.
    
    Returns:
        The ResourceManager instance
    """
    global _resource_manager
    if _resource_manager is None:
        _resource_manager = ResourceManager()
    return _resource_manager