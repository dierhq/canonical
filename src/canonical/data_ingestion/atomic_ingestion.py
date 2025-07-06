"""
Data ingestion script for Atomic Red Team tests.
"""

import asyncio
import json
import yaml
from typing import List, Dict, Any, Optional
from pathlib import Path
from loguru import logger
import git

from ..core.config import settings
from ..services.chromadb import chromadb_service


class AtomicIngestion:
    """Atomic Red Team tests ingestion."""
    
    def __init__(self):
        """Initialize the Atomic ingestion service."""
        self.repo_url = settings.atomic_repo_url
        self.collection_name = settings.atomic_collection
        self.repo_path = settings.repos_dir / "atomic-red-team"
    
    async def ingest_atomic_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Ingest Atomic Red Team tests data.
        
        Args:
            force_refresh: Whether to force refresh the data
            
        Returns:
            Ingestion statistics
        """
        logger.info("Starting Atomic Red Team ingestion")
        
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            # Clone or update repository
            await self._update_repository(force_refresh)
            
            # Find all atomic test files
            atomic_files = self._find_atomic_files()
            logger.info(f"Found {len(atomic_files)} Atomic Red Team files")
            
            # Process atomic tests
            stats = {
                "techniques": 0,
                "tests": 0,
                "total_processed": 0,
                "successful": 0,
                "failed": 0
            }
            
            for atomic_file in atomic_files:
                try:
                    technique_stats = await self._process_atomic_technique(atomic_file)
                    stats["techniques"] += 1
                    stats["tests"] += technique_stats["tests"]
                    stats["successful"] += technique_stats["successful"]
                    stats["failed"] += technique_stats["failed"]
                except Exception as e:
                    logger.error(f"Failed to process {atomic_file}: {e}")
                    stats["failed"] += 1
                
                stats["total_processed"] += 1
            
            logger.info(f"Atomic Red Team ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Atomic Red Team ingestion failed: {e}")
            raise
    
    async def _update_repository(self, force_refresh: bool = False) -> None:
        """Clone or update the Atomic Red Team repository.
        
        Args:
            force_refresh: Whether to force refresh the repository
        """
        try:
            if self.repo_path.exists() and not force_refresh:
                logger.info("Updating existing Atomic Red Team repository")
                repo = git.Repo(self.repo_path)
                repo.remotes.origin.pull()
            else:
                if self.repo_path.exists():
                    logger.info("Removing existing repository for fresh clone")
                    import shutil
                    shutil.rmtree(self.repo_path)
                
                logger.info(f"Cloning Atomic Red Team repository from {self.repo_url}")
                git.Repo.clone_from(self.repo_url, self.repo_path)
            
            logger.info("Atomic Red Team repository updated successfully")
        except Exception as e:
            logger.error(f"Failed to update Atomic Red Team repository: {e}")
            raise
    
    def _find_atomic_files(self) -> List[Path]:
        """Find all Atomic Red Team test files in the repository.
        
        Returns:
            List of Atomic test file paths
        """
        atomic_files = []
        
        # Look for .yml and .yaml files in the atomics directory
        atomics_dir = self.repo_path / "atomics"
        if atomics_dir.exists():
            for technique_dir in atomics_dir.iterdir():
                if technique_dir.is_dir():
                    # Look for the main technique file
                    technique_file = technique_dir / f"{technique_dir.name}.yaml"
                    if technique_file.exists():
                        atomic_files.append(technique_file)
        
        return atomic_files
    
    async def _process_atomic_technique(self, atomic_file: Path) -> Dict[str, int]:
        """Process an Atomic Red Team technique file.
        
        Args:
            atomic_file: Path to the atomic technique file
            
        Returns:
            Processing statistics
        """
        stats = {"tests": 0, "successful": 0, "failed": 0}
        
        try:
            # Read atomic technique content
            with open(atomic_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse YAML
            technique_data = yaml.safe_load(content)
            
            if not technique_data:
                return stats
            
            # Extract technique information
            technique_id = technique_data.get("attack_technique", "")
            technique_name = technique_data.get("display_name", "")
            
            # Process each atomic test
            atomic_tests = technique_data.get("atomic_tests", [])
            
            for i, test in enumerate(atomic_tests):
                try:
                    await self._process_atomic_test(test, technique_id, technique_name, i)
                    stats["tests"] += 1
                    stats["successful"] += 1
                except Exception as e:
                    logger.error(f"Failed to process test {i} in {atomic_file}: {e}")
                    stats["failed"] += 1
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to process atomic technique {atomic_file}: {e}")
            stats["failed"] += 1
            return stats
    
    async def _process_atomic_test(self, test: Dict[str, Any], technique_id: str, technique_name: str, test_index: int) -> None:
        """Process an individual atomic test.
        
        Args:
            test: Test data
            technique_id: MITRE technique ID
            technique_name: Technique name
            test_index: Test index within the technique
        """
        try:
            # Extract test information
            test_name = test.get("name", f"Test {test_index + 1}")
            test_description = test.get("description", "")
            
            # Extract platforms and executors
            platforms = test.get("supported_platforms", [])
            executor = test.get("executor", {})
            executor_name = executor.get("name", "")
            
            # Extract input arguments
            input_args = test.get("input_arguments", {})
            
            # Extract dependencies
            dependencies = test.get("dependencies", [])
            
            # Create document text for embedding
            document_text = f"""
            Atomic Red Team Test: {technique_id} - {test_name}
            Technique: {technique_name}
            Description: {test_description}
            Platforms: {', '.join(platforms)}
            Executor: {executor_name}
            Input Arguments: {len(input_args)} parameters
            Dependencies: {len(dependencies)} dependencies
            """.strip()
            
            # Create metadata
            metadata = {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "test_name": test_name,
                "test_description": test_description,
                "test_index": test_index,
                "platforms": json.dumps(platforms),
                "executor_name": executor_name,
                "executor": json.dumps(executor),
                "input_arguments": json.dumps(input_args),
                "dependencies": json.dumps(dependencies),
                "type": "atomic_test"
            }
            
            # Create unique ID
            test_id = f"atomic_{technique_id}_{test_index}"
            
            # Add to ChromaDB
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=[document_text],
                metadatas=[metadata],
                ids=[test_id]
            )
            
        except Exception as e:
            logger.error(f"Failed to process atomic test: {e}")
            raise
    
    async def search_tests(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Search for Atomic Red Team tests.
        
        Args:
            query: Search query
            n_results: Number of results to return
            
        Returns:
            List of matching tests
        """
        return await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=query,
            n_results=n_results
        )
    
    async def get_tests_by_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get Atomic tests for a specific MITRE technique.
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            List of associated tests
        """
        return await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=f"technique {technique_id}",
            n_results=50,
            where={"technique_id": technique_id}
        )
    
    async def get_tests_by_platform(self, platform: str) -> List[Dict[str, Any]]:
        """Get Atomic tests for a specific platform.
        
        Args:
            platform: Platform name (e.g., "windows", "linux", "macos")
            
        Returns:
            List of tests for the platform
        """
        return await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=f"platform {platform}",
            n_results=50,
            where={"platforms": {"$contains": platform}}
        )


# Global ingestion instance
atomic_ingestion = AtomicIngestion() 