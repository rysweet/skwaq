"""Parallel orchestration for code analysis.

This module provides functionality for orchestrating code analysis tasks
in parallel, improving performance for large codebases.
"""

import os
import asyncio
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import Any, Dict, List, Callable, Optional, Awaitable, TypeVar, Union, Set

from ..utils.logging import get_logger, LogEvent
from ..utils.config import get_config

logger = get_logger(__name__)

T = TypeVar('T')
R = TypeVar('R')


class ParallelOrchestrator:
    """Orchestrates parallel execution of code analysis tasks.
    
    This class provides functionality for executing code analysis tasks
    in parallel, utilizing available system resources efficiently.
    """
    
    def __init__(self, max_concurrency: Optional[int] = None):
        """Initialize the parallel orchestrator.
        
        Args:
            max_concurrency: Maximum number of concurrent tasks to execute.
                If None, defaults to CPU count.
        """
        self.config = get_config()
        
        # Set default concurrency to CPU count if not specified
        self.max_concurrency = max_concurrency or multiprocessing.cpu_count()
        
        # Load concurrency settings from config if available
        config_concurrency = self.config.get("analysis.max_concurrency")
        if config_concurrency is not None:
            try:
                self.max_concurrency = int(config_concurrency)
            except ValueError:
                logger.warning(
                    f"Invalid max_concurrency value in config: {config_concurrency}. "
                    f"Using default value: {self.max_concurrency}"
                )
        
        logger.info(f"Parallel orchestrator initialized with max concurrency: {self.max_concurrency}")
    
    @LogEvent("execute_parallel_tasks")
    async def execute_parallel_tasks(self, tasks: List[Awaitable[T]]) -> List[T]:
        """Execute a list of awaitable tasks in parallel.
        
        Args:
            tasks: List of awaitable tasks to execute in parallel
            
        Returns:
            List of results from executed tasks
        """
        if not tasks:
            return []
            
        logger.info(f"Executing {len(tasks)} tasks in parallel (max concurrency: {self.max_concurrency})")
        
        # Use asyncio.gather to run tasks concurrently with concurrency limit
        semaphore = asyncio.Semaphore(self.max_concurrency)
        
        async def bounded_task(task: Awaitable[T]) -> T:
            async with semaphore:
                return await task
                
        # Run all tasks with the semaphore
        return await asyncio.gather(*[bounded_task(task) for task in tasks])
    
    @LogEvent("parallelize_by_file")
    async def parallelize_by_file(
        self, 
        files: List[Dict[str, Any]], 
        task_generator: Callable[[Dict[str, Any]], Awaitable[R]]
    ) -> List[R]:
        """Process multiple files in parallel.
        
        Args:
            files: List of file dictionaries to process
            task_generator: Function to generate an awaitable task for each file
            
        Returns:
            List of results from executed tasks
        """
        tasks = [task_generator(file) for file in files]
        return await self.execute_parallel_tasks(tasks)
    
    @LogEvent("execute_cpu_bound_tasks")
    def execute_cpu_bound_tasks(
        self, 
        func: Callable[..., R], 
        args_list: List[List[Any]]
    ) -> List[R]:
        """Execute CPU-bound tasks in parallel using process pool.
        
        Args:
            func: Function to execute
            args_list: List of argument lists to pass to the function
            
        Returns:
            List of results from executed tasks
        """
        if not args_list:
            return []
            
        logger.info(f"Executing {len(args_list)} CPU-bound tasks in parallel")
        
        # Use process pool for CPU-bound tasks
        with ProcessPoolExecutor(max_workers=self.max_concurrency) as executor:
            results = list(executor.map(lambda args: func(*args), args_list))
            
        return results
    
    @LogEvent("execute_io_bound_tasks")
    def execute_io_bound_tasks(
        self, 
        func: Callable[..., R], 
        args_list: List[List[Any]]
    ) -> List[R]:
        """Execute IO-bound tasks in parallel using thread pool.
        
        Args:
            func: Function to execute
            args_list: List of argument lists to pass to the function
            
        Returns:
            List of results from executed tasks
        """
        if not args_list:
            return []
            
        logger.info(f"Executing {len(args_list)} IO-bound tasks in parallel")
        
        # Use thread pool for IO-bound tasks
        with ThreadPoolExecutor(max_workers=self.max_concurrency * 2) as executor:
            results = list(executor.map(lambda args: func(*args), args_list))
            
        return results
    
    @LogEvent("get_optimized_file_batches")
    def get_optimized_file_batches(
        self, 
        files: List[Dict[str, Any]], 
        batch_size: int = 0
    ) -> List[List[Dict[str, Any]]]:
        """Create optimized batches of files for parallel processing.
        
        This method attempts to group files by language and size to optimize
        parallel processing efficiency.
        
        Args:
            files: List of file dictionaries to batch
            batch_size: Size of each batch (0 for automatic sizing)
            
        Returns:
            List of file batches
        """
        if not files:
            return []
            
        # If batch_size is 0, calculate based on file count and concurrency
        if batch_size <= 0:
            # Aim for at least 2x concurrency level of batches to keep all cores busy
            batch_size = max(1, len(files) // (self.max_concurrency * 2))
            # But don't make batches too small
            batch_size = min(max(batch_size, 5), len(files))
        
        # Group files by language
        language_groups: Dict[str, List[Dict[str, Any]]] = {}
        
        for file in files:
            language = file.get("language", "unknown")
            if language not in language_groups:
                language_groups[language] = []
            language_groups[language].append(file)
        
        # Create batches by interleaving from different language groups
        batches = []
        current_batch = []
        
        # Sort languages by frequency to prioritize larger groups
        sorted_languages = sorted(
            language_groups.keys(), 
            key=lambda lang: len(language_groups[lang]), 
            reverse=True
        )
        
        # Create indices for each language group
        indices = {lang: 0 for lang in sorted_languages}
        
        # Continue until all files are assigned to batches
        while True:
            added_file = False
            
            for lang in sorted_languages:
                group = language_groups[lang]
                idx = indices[lang]
                
                if idx < len(group):
                    current_batch.append(group[idx])
                    indices[lang] += 1
                    added_file = True
                    
                    # Check if batch is full
                    if len(current_batch) >= batch_size:
                        batches.append(current_batch)
                        current_batch = []
            
            if not added_file:
                break
        
        # Add any remaining files
        if current_batch:
            batches.append(current_batch)
        
        logger.info(f"Created {len(batches)} optimized file batches from {len(files)} files")
        return batches