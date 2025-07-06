"""
Data ingestion script for Sigma rules from SigmaHQ repository.
"""

import asyncio
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import git
import yaml
from loguru import logger
from tqdm import tqdm

from ..core.config import settings
from ..services.chromadb import chromadb_service
from ..parsers.sigma import sigma_parser


class SigmaIngestion:
    """Sigma rules ingestion from SigmaHQ repository."""
    
    def __init__(self):
        """Initialize the Sigma ingestion service."""
        self.repo_path = settings.repos_dir / "sigma"
        self.repo_url = settings.sigma_repo_url
        self.collection_name = settings.sigma_collection
    
    async def ingest_sigma_rules(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Ingest Sigma rules from the SigmaHQ repository.
        
        Args:
            force_refresh: Whether to force refresh the repository
            
        Returns:
            Ingestion statistics
        """
        logger.info("Starting Sigma rules ingestion")
        
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            # Clone or update repository
            await self._update_repository(force_refresh)
            
            # Find all Sigma rule files
            rule_files = self._find_sigma_files()
            logger.info(f"Found {len(rule_files)} Sigma rule files")
            
            # Process rules in batches
            batch_size = 100
            total_processed = 0
            total_successful = 0
            total_failed = 0
            
            for i in range(0, len(rule_files), batch_size):
                batch = rule_files[i:i + batch_size]
                batch_results = await self._process_batch(batch)
                
                total_processed += len(batch)
                total_successful += batch_results["successful"]
                total_failed += batch_results["failed"]
                
                logger.info(f"Processed {total_processed}/{len(rule_files)} rules")
            
            stats = {
                "total_files": len(rule_files),
                "total_processed": total_processed,
                "successful": total_successful,
                "failed": total_failed,
                "collection": self.collection_name
            }
            
            logger.info(f"Sigma ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Sigma ingestion failed: {e}")
            raise
    
    async def _update_repository(self, force_refresh: bool = False) -> None:
        """Clone or update the Sigma repository.
        
        Args:
            force_refresh: Whether to force refresh the repository
        """
        try:
            if self.repo_path.exists() and not force_refresh:
                logger.info("Updating existing Sigma repository")
                repo = git.Repo(self.repo_path)
                repo.remotes.origin.pull()
            else:
                if self.repo_path.exists():
                    logger.info("Removing existing repository for fresh clone")
                    import shutil
                    shutil.rmtree(self.repo_path)
                
                logger.info(f"Cloning Sigma repository from {self.repo_url}")
                git.Repo.clone_from(self.repo_url, self.repo_path)
            
            logger.info("Sigma repository updated successfully")
        except Exception as e:
            logger.error(f"Failed to update Sigma repository: {e}")
            raise
    
    def _find_sigma_files(self) -> List[Path]:
        """Find all Sigma rule files in the repository.
        
        Returns:
            List of Sigma rule file paths
        """
        rule_files = []
        
        # Look for .yml and .yaml files in the rules directory
        rules_dir = self.repo_path / "rules"
        if rules_dir.exists():
            for file_path in rules_dir.rglob("*.yml"):
                rule_files.append(file_path)
            for file_path in rules_dir.rglob("*.yaml"):
                rule_files.append(file_path)
        
        return rule_files
    
    async def _process_batch(self, rule_files: List[Path]) -> Dict[str, int]:
        """Process a batch of Sigma rule files.
        
        Args:
            rule_files: List of rule file paths
            
        Returns:
            Batch processing statistics
        """
        documents = []
        metadatas = []
        ids = []
        
        successful = 0
        failed = 0
        
        for rule_file in rule_files:
            try:
                # Read rule content
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_content = f.read()
                
                # Parse rule
                parsed_rule = sigma_parser.parse_rule(rule_content)
                
                # Validate rule
                is_valid, errors = sigma_parser.validate_rule(parsed_rule)
                if not is_valid:
                    logger.warning(f"Invalid rule {rule_file}: {errors}")
                    failed += 1
                    continue
                
                # Create rule summary for embedding
                rule_summary = sigma_parser.extract_rule_summary(parsed_rule)
                
                # Extract metadata - serialize complex types for ChromaDB compatibility
                import json
                logsource_info = sigma_parser.get_log_source_info(parsed_rule)
                complexity_info = sigma_parser.analyze_rule_complexity(parsed_rule)
                
                metadata = {
                    "file_path": str(rule_file.relative_to(self.repo_path)),
                    "title": parsed_rule.title,
                    "description": parsed_rule.description or "",
                    "author": parsed_rule.author or "",
                    "date": parsed_rule.date or "",
                    "level": parsed_rule.level or "",
                    "status": parsed_rule.status or "",
                    "tags": json.dumps(parsed_rule.tags),  # Serialize list to JSON string
                    "mitre_techniques": json.dumps(sigma_parser.extract_mitre_tags(parsed_rule)),  # Serialize list to JSON string
                    "logsource_category": logsource_info.get("category", ""),
                    "logsource_product": logsource_info.get("product", ""),
                    "logsource_service": logsource_info.get("service", ""),
                    "complexity_level": complexity_info.get("complexity_level", "medium"),
                    "complexity_score": float(complexity_info.get("complexity_score", 0)),
                    "rule_id": parsed_rule.id or "",
                    "type": "sigma_rule"
                }
                
                # Create document ID
                doc_id = f"sigma_{parsed_rule.id or rule_file.stem}"
                
                documents.append(rule_summary)
                metadatas.append(metadata)
                ids.append(doc_id)
                
                successful += 1
                
            except Exception as e:
                logger.error(f"Failed to process rule {rule_file}: {e}")
                failed += 1
        
        # Add batch to ChromaDB
        if documents:
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
        
        return {"successful": successful, "failed": failed}
    
    async def search_rules(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Search for Sigma rules by query.
        
        Args:
            query: Search query
            n_results: Number of results to return
            
        Returns:
            List of matching rules
        """
        return await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=query,
            n_results=n_results
        )
    
    async def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific rule by ID.
        
        Args:
            rule_id: Rule ID to search for
            
        Returns:
            Rule data if found
        """
        results = await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=f"rule_id:{rule_id}",
            n_results=1,
            where={"rule_id": rule_id}
        )
        
        return results[0] if results else None
    
    async def get_rules_by_mitre_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get rules associated with a MITRE technique.
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            List of associated rules
        """
        return await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=f"MITRE technique {technique_id}",
            n_results=50,
            where={"mitre_techniques": {"$contains": technique_id}}
        )


# Global ingestion instance
sigma_ingestion = SigmaIngestion() 