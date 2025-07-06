"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Data ingestion script for MITRE CAR (Cyber Analytics Repository).
"""

import asyncio
import json
import requests
import yaml
from typing import List, Dict, Any, Optional
from pathlib import Path
from loguru import logger
import git

from ..core.config import settings
from ..services.chromadb import chromadb_service


class CarIngestion:
    """MITRE CAR (Cyber Analytics Repository) ingestion."""
    
    def __init__(self):
        """Initialize the CAR ingestion service."""
        self.repo_url = settings.car_repo_url
        self.collection_name = settings.car_collection
        self.repo_path = settings.repos_dir / "car"
    
    async def ingest_car_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Ingest MITRE CAR analytics data.
        
        Args:
            force_refresh: Whether to force refresh the data
            
        Returns:
            Ingestion statistics
        """
        logger.info("Starting MITRE CAR ingestion")
        
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            # Clone or update repository
            await self._update_repository(force_refresh)
            
            # Find all CAR analytics files
            analytics_files = self._find_car_files()
            logger.info(f"Found {len(analytics_files)} CAR analytics files")
            
            # Process analytics
            stats = {
                "analytics": 0,
                "total_processed": 0,
                "successful": 0,
                "failed": 0
            }
            
            for analytics_file in analytics_files:
                try:
                    await self._process_car_analytic(analytics_file)
                    stats["analytics"] += 1
                    stats["successful"] += 1
                except Exception as e:
                    logger.error(f"Failed to process {analytics_file}: {e}")
                    stats["failed"] += 1
                
                stats["total_processed"] += 1
            
            logger.info(f"MITRE CAR ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"MITRE CAR ingestion failed: {e}")
            raise
    
    async def _update_repository(self, force_refresh: bool = False) -> None:
        """Clone or update the CAR repository.
        
        Args:
            force_refresh: Whether to force refresh the repository
        """
        try:
            if self.repo_path.exists() and not force_refresh:
                logger.info("Updating existing CAR repository")
                repo = git.Repo(self.repo_path)
                repo.remotes.origin.pull()
            else:
                if self.repo_path.exists():
                    logger.info("Removing existing repository for fresh clone")
                    import shutil
                    shutil.rmtree(self.repo_path)
                
                logger.info(f"Cloning CAR repository from {self.repo_url}")
                git.Repo.clone_from(self.repo_url, self.repo_path)
            
            logger.info("CAR repository updated successfully")
        except Exception as e:
            logger.error(f"Failed to update CAR repository: {e}")
            raise
    
    def _find_car_files(self) -> List[Path]:
        """Find all CAR analytics files in the repository.
        
        Returns:
            List of CAR analytics file paths
        """
        analytics_files = []
        
        # Look for .yml and .yaml files in the analytics directory
        analytics_dir = self.repo_path / "analytics"
        if analytics_dir.exists():
            for file_path in analytics_dir.rglob("*.yml"):
                analytics_files.append(file_path)
            for file_path in analytics_dir.rglob("*.yaml"):
                analytics_files.append(file_path)
        
        return analytics_files
    
    async def _process_car_analytic(self, analytics_file: Path) -> None:
        """Process a CAR analytics file.
        
        Args:
            analytics_file: Path to the analytics file
        """
        try:
            # Read analytics content
            with open(analytics_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse YAML
            analytics_data = yaml.safe_load(content)
            
            if not analytics_data:
                return
            
            # Extract CAR ID
            car_id = analytics_data.get("id", "")
            if not car_id:
                car_id = analytics_file.stem
            
            # Extract title and description
            title = analytics_data.get("title", "")
            description = analytics_data.get("description", "")
            
            # Extract MITRE ATT&CK mappings
            mitre_techniques = []
            coverage = analytics_data.get("coverage", [])
            for cov in coverage:
                technique = cov.get("technique", "")
                if technique:
                    mitre_techniques.append(technique)
            
            # Extract data model references
            data_model_refs = analytics_data.get("data_model_references", [])
            
            # Extract implementations
            implementations = analytics_data.get("implementations", [])
            
            # Create document text for embedding
            document_text = f"""
            MITRE CAR Analytics: {car_id}
            Title: {title}
            Description: {description}
            MITRE ATT&CK Techniques: {', '.join(mitre_techniques)}
            Data Model References: {', '.join(data_model_refs)}
            Implementations: {len(implementations)} available
            """.strip()
            
            # Create metadata
            metadata = {
                "car_id": car_id,
                "title": title,
                "description": description,
                "mitre_techniques": json.dumps(mitre_techniques),
                "data_model_refs": json.dumps(data_model_refs),
                "implementations_count": len(implementations),
                "implementations": json.dumps(implementations),
                "coverage": json.dumps(coverage),
                "type": "car_analytic",
                "file_path": str(analytics_file.relative_to(self.repo_path)),
                "created": analytics_data.get("created", ""),
                "modified": analytics_data.get("modified", "")
            }
            
            # Add to ChromaDB
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=[document_text],
                metadatas=[metadata],
                ids=[f"car_{car_id}"]
            )
            
        except Exception as e:
            logger.error(f"Failed to process CAR analytic {analytics_file}: {e}")
            raise
    
    async def search_analytics(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Search for CAR analytics.
        
        Args:
            query: Search query
            n_results: Number of results to return
            
        Returns:
            List of matching analytics
        """
        return await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=query,
            n_results=n_results
        )
    
    async def get_analytic_by_id(self, car_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific CAR analytic by ID.
        
        Args:
            car_id: CAR ID to search for
            
        Returns:
            CAR analytic data if found
        """
        results = await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=f"CAR {car_id}",
            n_results=1,
            where={"car_id": car_id}
        )
        
        return results[0] if results else None
    
    async def get_analytics_by_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get CAR analytics associated with a MITRE technique.
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            List of associated analytics
        """
        return await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=f"MITRE technique {technique_id}",
            n_results=50,
            where={"mitre_techniques": {"$contains": technique_id}}
        )


# Global ingestion instance
car_ingestion = CarIngestion() 