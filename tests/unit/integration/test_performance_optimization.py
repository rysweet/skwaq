"""Unit tests for skwaq.integration.performance_optimization module."""

import pytest
import time
from unittest.mock import MagicMock, patch

from skwaq.integration.performance_optimization import (
    QueryOptimizer,
    DatabaseOptimization,
    MemoryOptimization,
    get_query_optimizer,
    get_db_optimization,
    get_memory_optimization,
)


class TestQueryOptimizer:
    """Tests for the QueryOptimizer class."""

    def test_init(self):
        """Test initialization."""
        optimizer = QueryOptimizer()
        assert optimizer is not None
        assert optimizer.query_stats == {}
        assert optimizer.slow_queries == []
        assert optimizer.query_count == 0

    def test_measure_query(self):
        """Test the measure_query decorator."""
        optimizer = QueryOptimizer()

        # Create a function to decorate
        @optimizer.measure_query("SELECT * FROM test", threshold_ms=10)
        def test_function():
            time.sleep(0.02)  # Sleep to ensure execution time > threshold
            return "result"

        # Call the decorated function
        result = test_function()

        # Verify results
        assert result == "result"
        assert optimizer.query_count == 1
        assert len(optimizer.query_stats) == 1
        assert len(optimizer.slow_queries) == 1

        # Get stats
        stats = optimizer.get_query_stats()
        assert stats["query_count"] == 1
        assert stats["unique_queries"] == 1
        assert stats["slow_query_count"] == 1

        # Get slow queries
        slow_queries = optimizer.get_slow_queries()
        assert len(slow_queries) == 1
        assert slow_queries[0]["query"] == "SELECT * FROM test"

    def test_record_query_stat(self):
        """Test recording query statistics."""
        optimizer = QueryOptimizer()

        # Record a query stat
        optimizer._record_query_stat("SELECT * FROM test", 150.0)

        # Verify stats were recorded
        assert optimizer.query_count == 1
        assert len(optimizer.query_stats) == 1

        query_hash = hash("SELECT * FROM test")
        assert query_hash in optimizer.query_stats
        stats = optimizer.query_stats[query_hash]
        assert stats["query"] == "SELECT * FROM test"
        assert stats["count"] == 1
        assert stats["total_time"] == 150.0
        assert stats["min_time"] == 150.0
        assert stats["max_time"] == 150.0
        assert stats["avg_time"] == 150.0

        # Record another execution of the same query
        optimizer._record_query_stat("SELECT * FROM test", 50.0)

        # Verify stats were updated
        assert optimizer.query_count == 2
        assert len(optimizer.query_stats) == 1
        stats = optimizer.query_stats[query_hash]
        assert stats["count"] == 2
        assert stats["total_time"] == 200.0
        assert stats["min_time"] == 50.0
        assert stats["max_time"] == 150.0
        assert stats["avg_time"] == 100.0

    def test_record_slow_query(self):
        """Test recording slow queries."""
        optimizer = QueryOptimizer()

        # Record a slow query
        optimizer._record_slow_query(
            "SELECT * FROM test WHERE id = ?", {"id": 123}, 250.0
        )

        # Verify query was recorded
        assert len(optimizer.slow_queries) == 1
        slow_query = optimizer.slow_queries[0]
        assert slow_query["query"] == "SELECT * FROM test WHERE id = ?"
        assert slow_query["params"] == {"id": 123}
        assert slow_query["execution_time"] == 250.0
        assert "timestamp" in slow_query

        # Record multiple slow queries and check limit
        for i in range(101):
            optimizer._record_slow_query(f"SELECT {i}", None, 100.0)

        # Verify oldest query was removed when limit reached
        assert len(optimizer.slow_queries) == 100
        assert optimizer.slow_queries[0]["query"] != "SELECT * FROM test WHERE id = ?"

    def test_analyze_query(self):
        """Test query analysis."""
        optimizer = QueryOptimizer()

        # Analyze different types of queries
        result1 = optimizer.analyze_query("MATCH (n) RETURN n")
        result2 = optimizer.analyze_query(
            "MATCH (n:Label) WHERE n.prop = 'value' RETURN n"
        )
        result3 = optimizer.analyze_query(
            "MATCH (n) OPTIONAL MATCH (n)-[:REL1]->(m) OPTIONAL MATCH (n)-[:REL2]->(p) OPTIONAL MATCH (n)-[:REL3]->(q) RETURN n,m,p,q"
        )

        # Verify analysis results
        assert "issues" in result1
        assert "suggestions" in result1
        assert any("without WHERE clause" in issue for issue in result1["issues"])

        assert "issues" in result3
        assert any("Multiple OPTIONAL MATCH" in issue for issue in result3["issues"])

        # Query with no issues should still have empty lists
        assert "issues" in result2
        assert len(result2["issues"]) == 0

    def test_optimize_query(self):
        """Test query optimization."""
        optimizer = QueryOptimizer()

        # Optimize different queries
        optimized1 = optimizer.optimize_query("MATCH (n) RETURN n")
        optimized2 = optimizer.optimize_query("MATCH (n:Label) RETURN n")

        # Verify optimizations
        assert "MATCH (n)" not in optimized1
        assert "Add a label for better performance" in optimized1
        assert "USING INDEX" in optimized2


class TestDatabaseOptimization:
    """Tests for the DatabaseOptimization class."""

    def test_init(self):
        """Test initialization."""
        db_optimization = DatabaseOptimization()
        assert db_optimization is not None
        assert hasattr(db_optimization, "query_optimizer")
        assert db_optimization.cache_hit_count == 0
        assert db_optimization.cache_miss_count == 0

    def test_cached_query_decorator(self):
        """Test the cached_query decorator."""
        db_optimization = DatabaseOptimization()

        # Create a mock cache
        mock_cache = MagicMock()
        mock_cache.get.return_value = None  # Simulate cache miss first

        # Setup mocks
        with patch(
            "skwaq.integration.performance_optimization.get_performance_optimizer"
        ) as mock_get_optimizer:
            mock_optimizer = MagicMock()
            mock_optimizer.cache = mock_cache
            mock_get_optimizer.return_value = mock_optimizer

            # Create a function to decorate
            @db_optimization.cached_query(ttl=60)
            def test_function(arg1, arg2):
                return f"result: {arg1}, {arg2}"

            # First call - cache miss
            result1 = test_function("test1", "test2")

            # Verify results and cache behavior
            assert result1 == "result: test1, test2"
            assert db_optimization.cache_hit_count == 0
            assert db_optimization.cache_miss_count == 1

            # Verify cache set was called
            mock_cache.set.assert_called_once()

            # Setup cache hit for second call
            mock_cache.get.return_value = "cached result"

            # Second call - cache hit
            result2 = test_function("test1", "test2")

            # Verify results and cache behavior
            assert result2 == "cached result"
            assert db_optimization.cache_hit_count == 1
            assert db_optimization.cache_miss_count == 1

    @pytest.mark.asyncio
    async def test_cached_query_async_decorator(self):
        """Test the cached_query_async decorator."""
        db_optimization = DatabaseOptimization()

        # Create a mock cache
        mock_cache = MagicMock()
        mock_cache.get.return_value = None  # Simulate cache miss first

        # Setup mocks
        with patch(
            "skwaq.integration.performance_optimization.get_performance_optimizer"
        ) as mock_get_optimizer:
            mock_optimizer = MagicMock()
            mock_optimizer.cache = mock_cache
            mock_get_optimizer.return_value = mock_optimizer

            # Create an async function to decorate
            decorator = await db_optimization.cached_query_async(ttl=60)

            @decorator
            async def test_async_function(arg1, arg2):
                return f"async result: {arg1}, {arg2}"

            # First call - cache miss
            result1 = await test_async_function("test1", "test2")

            # Verify results and cache behavior
            assert result1 == "async result: test1, test2"
            assert db_optimization.cache_hit_count == 0
            assert db_optimization.cache_miss_count == 1

            # Verify cache set was called
            mock_cache.set.assert_called_once()

            # Setup cache hit for second call
            mock_cache.get.return_value = "cached async result"

            # Second call - cache hit
            result2 = await test_async_function("test1", "test2")

            # Verify results and cache behavior
            assert result2 == "cached async result"
            assert db_optimization.cache_hit_count == 1
            assert db_optimization.cache_miss_count == 1

    @patch("skwaq.integration.performance_optimization.get_connector")
    def test_optimize_connection_pool(self, mock_get_connector):
        """Test connection pool optimization."""
        db_optimization = DatabaseOptimization()

        # Test with connector not available
        mock_get_connector.return_value = None
        db_optimization.optimize_connection_pool()

        # Test with connector available
        mock_connector = MagicMock()
        mock_get_connector.return_value = mock_connector
        db_optimization.optimize_connection_pool()

    def test_get_cache_stats(self):
        """Test getting cache statistics."""
        db_optimization = DatabaseOptimization()

        # Set some test data
        db_optimization.cache_hit_count = 75
        db_optimization.cache_miss_count = 25

        # Get stats
        stats = db_optimization.get_cache_stats()

        # Verify results
        assert stats["cache_hits"] == 75
        assert stats["cache_misses"] == 25
        assert stats["hit_rate"] == 0.75  # 75 / (75 + 25) = 0.75

        # Test with zero requests
        db_optimization.cache_hit_count = 0
        db_optimization.cache_miss_count = 0

        # Get stats again
        stats = db_optimization.get_cache_stats()

        # Verify results
        assert stats["hit_rate"] == 0  # Avoid division by zero


class TestMemoryOptimization:
    """Tests for the MemoryOptimization class."""

    def test_init(self):
        """Test initialization."""
        # Test when psutil is available (default case)
        memory_optimization = MemoryOptimization()
        assert memory_optimization is not None
        assert hasattr(memory_optimization, "psutil_available")

    @patch("skwaq.integration.performance_optimization.logger")
    def test_unavailable_methods(self, mock_logger):
        """Test methods when psutil is not available."""
        # Create a memory optimization instance with psutil set as unavailable
        memory_optimization = MemoryOptimization()
        memory_optimization.psutil_available = False

        # Test methods that require psutil
        snapshot = memory_optimization.take_memory_snapshot()
        assert "error" in snapshot

        usage = memory_optimization.get_memory_usage()
        assert "error" in usage

        trend = memory_optimization.analyze_memory_trend()
        assert "error" in trend

        optimization = memory_optimization.optimize_memory_usage()
        assert "error" in optimization

    def test_analyze_memory_trend(self):
        """Test analyzing memory trends."""
        memory_optimization = MemoryOptimization()

        # Test with no snapshots
        result = memory_optimization.analyze_memory_trend()
        assert "error" in result
        assert "Not enough snapshots" in result["error"]

        # Add test snapshots
        memory_optimization.memory_snapshots = [
            {
                "timestamp": "2023-01-01T00:00:00",
                "rss": 1000000000,
                "vms": 2000000000,
                "percent": 5.0,
            },
            {
                "timestamp": "2023-01-01T00:05:00",
                "rss": 1100000000,  # 10% growth
                "vms": 2100000000,
                "percent": 5.5,
            },
        ]

        # Analyze trend
        result = memory_optimization.analyze_memory_trend()

        # Verify results
        assert "snapshots" in result
        assert result["snapshots"] == 2
        assert result["first_timestamp"] == "2023-01-01T00:00:00"
        assert result["last_timestamp"] == "2023-01-01T00:05:00"
        assert result["rss_growth_bytes"] == 100000000
        assert result["rss_growth_percent"] == 10.0
        assert result["trend"] == "growing"

        # Test with missing data
        memory_optimization.memory_snapshots = [
            {"timestamp": "2023-01-01T00:00:00"},
            {"timestamp": "2023-01-01T00:05:00"},
        ]

        # Analyze trend with missing data
        result = memory_optimization.analyze_memory_trend()

        # Verify error handling
        assert "error" in result
        assert "Incomplete snapshot data" in result["error"]


def test_get_query_optimizer():
    """Test the get_query_optimizer function."""
    # Create a placeholder test
    optimizer = get_query_optimizer()
    assert optimizer is not None


def test_get_db_optimization():
    """Test the get_db_optimization function."""
    # Create a placeholder test
    optimization = get_db_optimization()
    assert optimization is not None


def test_get_memory_optimization():
    """Test the get_memory_optimization function."""
    # Create a placeholder test
    optimization = get_memory_optimization()
    assert optimization is not None
