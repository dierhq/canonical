"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Data ingestion script for Azure Sentinel detection rules and hunting queries.
"""

import asyncio
import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import git
import yaml
from loguru import logger
from tqdm import tqdm

from ..core.config import settings
from ..core.models import AzureSentinelDetection, AzureSentinelHuntingQuery
from ..services.chromadb import chromadb_service


class AzureSentinelIngestion:
    """Azure Sentinel rules and hunting queries ingestion."""
    
    def __init__(self):
        """Initialize the Azure Sentinel ingestion service."""
        self.repo_path = settings.repos_dir / "azure-sentinel"
        self.repo_url = settings.azure_sentinel_repo_url
        self.detections_collection = settings.azure_sentinel_detections_collection
        self.hunting_collection = settings.azure_sentinel_hunting_collection
    
    async def ingest_all(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Ingest both detection rules and hunting queries.
        
        Args:
            force_refresh: Whether to force refresh the repository
            
        Returns:
            Combined ingestion statistics
        """
        logger.info("Starting Azure Sentinel ingestion (detections + hunting)")
        
        # Initialize ChromaDB service
        await chromadb_service.initialize()
        
        # Clone or update repository
        await self._update_repository(force_refresh)
        
        # Ingest detections and hunting queries in parallel
        detection_task = self.ingest_detections()
        hunting_task = self.ingest_hunting_queries()
        
        detection_stats, hunting_stats = await asyncio.gather(
            detection_task, hunting_task, return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(detection_stats, Exception):
            logger.error(f"Detection ingestion failed: {detection_stats}")
            detection_stats = {"error": str(detection_stats)}
        
        if isinstance(hunting_stats, Exception):
            logger.error(f"Hunting ingestion failed: {hunting_stats}")
            hunting_stats = {"error": str(hunting_stats)}
        
        combined_stats = {
            "detections": detection_stats,
            "hunting": hunting_stats,
            "total_successful": (
                detection_stats.get("successful", 0) + 
                hunting_stats.get("successful", 0)
            ),
            "total_failed": (
                detection_stats.get("failed", 0) + 
                hunting_stats.get("failed", 0)
            )
        }
        
        logger.info(f"Azure Sentinel ingestion completed: {combined_stats}")
        return combined_stats
    
    async def ingest_detections(self) -> Dict[str, Any]:
        """Ingest Azure Sentinel detection rules.
        
        Returns:
            Detection ingestion statistics
        """
        logger.info("Starting Azure Sentinel detection rules ingestion")
        
        try:
            # Find all detection rule files
            detection_files = self._find_detection_files()
            logger.info(f"Found {len(detection_files)} detection rule files")
            
            # Process rules in batches
            batch_size = 50
            total_processed = 0
            total_successful = 0
            total_failed = 0
            
            for i in range(0, len(detection_files), batch_size):
                batch = detection_files[i:i + batch_size]
                batch_results = await self._process_detection_batch(batch)
                
                total_processed += len(batch)
                total_successful += batch_results["successful"]
                total_failed += batch_results["failed"]
                
                logger.info(f"Processed {total_processed}/{len(detection_files)} detection rules")
            
            stats = {
                "total_files": len(detection_files),
                "total_processed": total_processed,
                "successful": total_successful,
                "failed": total_failed,
                "collection": self.detections_collection
            }
            
            logger.info(f"Detection ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Detection ingestion failed: {e}")
            raise
    
    async def ingest_hunting_queries(self) -> Dict[str, Any]:
        """Ingest Azure Sentinel hunting queries.
        
        Returns:
            Hunting ingestion statistics
        """
        logger.info("Starting Azure Sentinel hunting queries ingestion")
        
        try:
            # Find all hunting query files
            hunting_files = self._find_hunting_files()
            logger.info(f"Found {len(hunting_files)} hunting query files")
            
            # Process queries in batches
            batch_size = 50
            total_processed = 0
            total_successful = 0
            total_failed = 0
            
            for i in range(0, len(hunting_files), batch_size):
                batch = hunting_files[i:i + batch_size]
                batch_results = await self._process_hunting_batch(batch)
                
                total_processed += len(batch)
                total_successful += batch_results["successful"]
                total_failed += batch_results["failed"]
                
                logger.info(f"Processed {total_processed}/{len(hunting_files)} hunting queries")
            
            stats = {
                "total_files": len(hunting_files),
                "total_processed": total_processed,
                "successful": total_successful,
                "failed": total_failed,
                "collection": self.hunting_collection
            }
            
            logger.info(f"Hunting ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Hunting ingestion failed: {e}")
            raise
    
    async def _update_repository(self, force_refresh: bool = False) -> None:
        """Clone or update the Azure Sentinel repository.
        
        Args:
            force_refresh: Whether to force refresh the repository
        """
        try:
            if self.repo_path.exists() and not force_refresh:
                logger.info("Updating existing Azure Sentinel repository")
                repo = git.Repo(self.repo_path)
                repo.remotes.origin.pull()
            else:
                if self.repo_path.exists():
                    logger.info("Removing existing repository for fresh clone")
                    import shutil
                    shutil.rmtree(self.repo_path)
                
                logger.info(f"Cloning Azure Sentinel repository from {self.repo_url}")
                git.Repo.clone_from(self.repo_url, self.repo_path)
            
            logger.info("Azure Sentinel repository updated successfully")
        except Exception as e:
            logger.error(f"Failed to update Azure Sentinel repository: {e}")
            raise
    
    def _find_detection_files(self) -> List[Path]:
        """Find all detection rule files in the repository.
        
        Returns:
            List of detection rule file paths
        """
        detection_files = []
        
        # Look for detection rules in the Detections directory
        detections_dir = self.repo_path / "Detections"
        if detections_dir.exists():
            # Look for YAML files (detection rules)
            for file_path in detections_dir.rglob("*.yaml"):
                detection_files.append(file_path)
            for file_path in detections_dir.rglob("*.yml"):
                detection_files.append(file_path)
        
        return detection_files
    
    def _find_hunting_files(self) -> List[Path]:
        """Find all hunting query files in the repository.
        
        Returns:
            List of hunting query file paths
        """
        hunting_files = []
        
        # Look for hunting queries in the Hunting Queries directory
        hunting_dir = self.repo_path / "Hunting Queries"
        if hunting_dir.exists():
            # Look for KQL files (hunting queries)
            for file_path in hunting_dir.rglob("*.kql"):
                hunting_files.append(file_path)
            for file_path in hunting_dir.rglob("*.kusto"):
                hunting_files.append(file_path)
            # Also look for YAML files that might contain hunting queries
            for file_path in hunting_dir.rglob("*.yaml"):
                hunting_files.append(file_path)
            for file_path in hunting_dir.rglob("*.yml"):
                hunting_files.append(file_path)
        
        return hunting_files
    
    async def _process_detection_batch(self, detection_files: List[Path]) -> Dict[str, int]:
        """Process a batch of detection rule files.
        
        Args:
            detection_files: List of detection rule file paths
            
        Returns:
            Batch processing statistics
        """
        documents = []
        metadatas = []
        ids = []
        
        successful = 0
        failed = 0
        
        for detection_file in detection_files:
            try:
                # Read and parse detection rule
                detection_rule = self._parse_detection_file(detection_file)
                if not detection_rule:
                    failed += 1
                    continue
                
                # Validate detection rule
                is_valid, errors = self._validate_detection(detection_rule)
                if not is_valid:
                    logger.warning(f"Invalid detection rule {detection_file}: {errors}")
                    failed += 1
                    continue
                
                # Create rule summary for embedding
                rule_summary = self._create_detection_summary(detection_rule)
                
                # Create metadata for ChromaDB
                metadata = self._create_detection_metadata(detection_rule, detection_file)
                
                # Create document ID
                doc_id = f"azure_detection_{detection_rule.rule_id or detection_file.stem}"
                
                documents.append(rule_summary)
                metadatas.append(metadata)
                ids.append(doc_id)
                
                successful += 1
                
            except Exception as e:
                logger.error(f"Failed to process detection file {detection_file}: {e}")
                failed += 1
        
        # Add to ChromaDB
        if documents:
            await chromadb_service.add_documents(
                collection_name=self.detections_collection,
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
        
        return {"successful": successful, "failed": failed}
    
    async def _process_hunting_batch(self, hunting_files: List[Path]) -> Dict[str, int]:
        """Process a batch of hunting query files.
        
        Args:
            hunting_files: List of hunting query file paths
            
        Returns:
            Batch processing statistics
        """
        documents = []
        metadatas = []
        ids = []
        
        successful = 0
        failed = 0
        
        for hunting_file in hunting_files:
            try:
                # Read and parse hunting query
                hunting_query = self._parse_hunting_file(hunting_file)
                if not hunting_query:
                    failed += 1
                    continue
                
                # Validate hunting query
                is_valid, errors = self._validate_hunting_query(hunting_query)
                if not is_valid:
                    logger.warning(f"Invalid hunting query {hunting_file}: {errors}")
                    failed += 1
                    continue
                
                # Create query summary for embedding
                query_summary = self._create_hunting_summary(hunting_query)
                
                # Create metadata for ChromaDB
                metadata = self._create_hunting_metadata(hunting_query, hunting_file)
                
                # Create document ID
                doc_id = f"azure_hunting_{hunting_query.query_id or hunting_file.stem}"
                
                documents.append(query_summary)
                metadatas.append(metadata)
                ids.append(doc_id)
                
                successful += 1
                
            except Exception as e:
                logger.error(f"Failed to process hunting file {hunting_file}: {e}")
                failed += 1
        
        # Add to ChromaDB
        if documents:
            await chromadb_service.add_documents(
                collection_name=self.hunting_collection,
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
        
        return {"successful": successful, "failed": failed}
    
    def _parse_detection_file(self, file_path: Path) -> Optional[AzureSentinelDetection]:
        """Parse a detection rule file.
        
        Args:
            file_path: Path to the detection rule file
            
        Returns:
            Parsed AzureSentinelDetection object or None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try to parse as YAML
            try:
                data = yaml.safe_load(content)
                if not isinstance(data, dict):
                    return None
                
                # Extract detection rule fields
                detection = AzureSentinelDetection(
                    rule_id=data.get("id"),
                    name=data.get("name", ""),
                    description=data.get("description", ""),
                    severity=data.get("severity", "Medium"),
                    query=data.get("query", ""),
                    query_frequency=data.get("queryFrequency"),
                    query_period=data.get("queryPeriod"),
                    trigger_operator=data.get("triggerOperator"),
                    trigger_threshold=data.get("triggerThreshold"),
                    tactics=data.get("tactics") or [],
                    techniques=data.get("techniques") or [],
                    display_name=data.get("displayName"),
                    enabled=data.get("enabled", True),
                    suppression_enabled=data.get("suppressionEnabled", False),
                    suppression_duration=data.get("suppressionDuration"),
                    event_grouping=data.get("eventGroupingSettings"),
                    alert_details_override=data.get("alertDetailsOverride"),
                    custom_details=data.get("customDetails"),
                    entity_mappings=data.get("entityMappings") or [],
                    author=data.get("author"),
                    created_date=data.get("createdDate"),
                    last_modified=data.get("lastModified"),
                    version=data.get("version")
                )
                
                # Extract MITRE techniques
                detection.mitre_techniques = self._extract_mitre_from_detection(detection)
                
                return detection
                
            except yaml.YAMLError:
                # If YAML parsing fails, try to extract from raw content
                return self._parse_detection_from_text(content, file_path)
                
        except Exception as e:
            logger.error(f"Failed to parse detection file {file_path}: {e}")
            return None
    
    def _parse_hunting_file(self, file_path: Path) -> Optional[AzureSentinelHuntingQuery]:
        """Parse a hunting query file.
        
        Args:
            file_path: Path to the hunting query file
            
        Returns:
            Parsed AzureSentinelHuntingQuery object or None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check file extension
            if file_path.suffix.lower() in ['.kql', '.kusto']:
                # Parse KQL file
                return self._parse_kql_file(content, file_path)
            elif file_path.suffix.lower() in ['.yaml', '.yml']:
                # Parse YAML file
                return self._parse_hunting_yaml(content, file_path)
            else:
                logger.warning(f"Unsupported hunting file format: {file_path}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to parse hunting file {file_path}: {e}")
            return None
    
    def _parse_kql_file(self, content: str, file_path: Path) -> Optional[AzureSentinelHuntingQuery]:
        """Parse a KQL hunting query file.
        
        Args:
            content: File content
            file_path: Path to the file
            
        Returns:
            Parsed AzureSentinelHuntingQuery object or None
        """
        try:
            # Extract metadata from comments
            metadata = self._extract_kql_metadata(content)
            
            # Extract the actual query (remove comments)
            query_lines = []
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('//'):
                    query_lines.append(line)
            
            query = '\n'.join(query_lines)
            
            hunting_query = AzureSentinelHuntingQuery(
                query_id=metadata.get("id"),
                name=metadata.get("name", file_path.stem),
                description=metadata.get("description", ""),
                query=query,
                data_types=metadata.get("data_types", []),
                tactics=metadata.get("tactics", []),
                techniques=metadata.get("techniques", []),
                required_data_connectors=metadata.get("required_data_connectors", []),
                author=metadata.get("author"),
                created_date=metadata.get("created_date"),
                last_modified=metadata.get("last_modified"),
                version=metadata.get("version")
            )
            
            # Extract MITRE techniques
            hunting_query.mitre_techniques = self._extract_mitre_from_hunting(hunting_query)
            
            return hunting_query
            
        except Exception as e:
            logger.error(f"Failed to parse KQL file {file_path}: {e}")
            return None
    
    def _extract_kql_metadata(self, content: str) -> Dict[str, Any]:
        """Extract metadata from KQL file comments.
        
        Args:
            content: KQL file content
            
        Returns:
            Dictionary of extracted metadata
        """
        metadata = {}
        
        # Common metadata patterns in KQL comments
        patterns = {
            "name": r"//\s*(?:Name|Title):\s*(.+)",
            "description": r"//\s*(?:Description|Desc):\s*(.+)",
            "author": r"//\s*(?:Author|Created by):\s*(.+)",
            "created_date": r"//\s*(?:Created|Date):\s*(.+)",
            "version": r"//\s*(?:Version|Ver):\s*(.+)",
            "tactics": r"//\s*(?:Tactics|MITRE Tactics):\s*(.+)",
            "techniques": r"//\s*(?:Techniques|MITRE Techniques):\s*(.+)",
            "data_types": r"//\s*(?:Data Types|DataTypes):\s*(.+)",
        }
        
        for field, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                value = matches[0].strip()
                if field in ["tactics", "techniques", "data_types"]:
                    # Split comma-separated values
                    metadata[field] = [item.strip() for item in value.split(',') if item.strip()]
                else:
                    metadata[field] = value
        
        return metadata
    
    def _extract_mitre_from_detection(self, detection: AzureSentinelDetection) -> List[str]:
        """Extract MITRE techniques from detection rule.
        
        Args:
            detection: AzureSentinelDetection object
            
        Returns:
            List of MITRE technique IDs
        """
        techniques = []
        
        # Add techniques from the techniques field
        techniques.extend(detection.techniques)
        
        # Look for MITRE patterns in description and query
        text_to_search = f"{detection.description or ''} {detection.query}"
        mitre_patterns = [
            r"T\d{4}(?:\.\d{3})?",  # Standard MITRE technique format
            r"(?:MITRE|ATT&CK).*?(T\d{4}(?:\.\d{3})?)",  # MITRE context
        ]
        
        for pattern in mitre_patterns:
            matches = re.findall(pattern, text_to_search, re.IGNORECASE)
            techniques.extend(matches)
        
        return list(set(techniques))  # Remove duplicates
    
    def _extract_mitre_from_hunting(self, hunting_query: AzureSentinelHuntingQuery) -> List[str]:
        """Extract MITRE techniques from hunting query.
        
        Args:
            hunting_query: AzureSentinelHuntingQuery object
            
        Returns:
            List of MITRE technique IDs
        """
        techniques = []
        
        # Add techniques from the techniques field
        techniques.extend(hunting_query.techniques)
        
        # Look for MITRE patterns in description and query
        text_to_search = f"{hunting_query.description or ''} {hunting_query.query}"
        mitre_patterns = [
            r"T\d{4}(?:\.\d{3})?",  # Standard MITRE technique format
            r"(?:MITRE|ATT&CK).*?(T\d{4}(?:\.\d{3})?)",  # MITRE context
        ]
        
        for pattern in mitre_patterns:
            matches = re.findall(pattern, text_to_search, re.IGNORECASE)
            techniques.extend(matches)
        
        return list(set(techniques))  # Remove duplicates
    
    def _create_detection_summary(self, detection: AzureSentinelDetection) -> str:
        """Create a summary for detection rule embedding.
        
        Args:
            detection: AzureSentinelDetection object
            
        Returns:
            Detection rule summary string
        """
        summary_parts = []
        
        summary_parts.append(f"Detection Rule: {detection.name}")
        if detection.description:
            summary_parts.append(f"Description: {detection.description}")
        
        summary_parts.append(f"Severity: {detection.severity}")
        
        if detection.tactics:
            summary_parts.append(f"Tactics: {', '.join(detection.tactics)}")
        
        if detection.mitre_techniques:
            summary_parts.append(f"MITRE Techniques: {', '.join(detection.mitre_techniques)}")
        
        if detection.query:
            # Add a truncated version of the query
            query_preview = detection.query[:200] + "..." if len(detection.query) > 200 else detection.query
            summary_parts.append(f"Query: {query_preview}")
        
        return " | ".join(summary_parts)
    
    def _create_hunting_summary(self, hunting_query: AzureSentinelHuntingQuery) -> str:
        """Create a summary for hunting query embedding.
        
        Args:
            hunting_query: AzureSentinelHuntingQuery object
            
        Returns:
            Hunting query summary string
        """
        summary_parts = []
        
        summary_parts.append(f"Hunting Query: {hunting_query.name}")
        if hunting_query.description:
            summary_parts.append(f"Description: {hunting_query.description}")
        
        if hunting_query.tactics:
            summary_parts.append(f"Tactics: {', '.join(hunting_query.tactics)}")
        
        if hunting_query.data_types:
            summary_parts.append(f"Data Types: {', '.join(hunting_query.data_types)}")
        
        if hunting_query.mitre_techniques:
            summary_parts.append(f"MITRE Techniques: {', '.join(hunting_query.mitre_techniques)}")
        
        if hunting_query.query:
            # Add a truncated version of the query
            query_preview = hunting_query.query[:200] + "..." if len(hunting_query.query) > 200 else hunting_query.query
            summary_parts.append(f"Query: {query_preview}")
        
        return " | ".join(summary_parts)
    
    def _create_detection_metadata(self, detection: AzureSentinelDetection, file_path: Path) -> Dict[str, Any]:
        """Create metadata for detection rule ChromaDB storage.
        
        Args:
            detection: AzureSentinelDetection object
            file_path: Path to the detection file
            
        Returns:
            Metadata dictionary
        """
        return {
            "file_path": str(file_path.relative_to(self.repo_path)),
            "rule_id": detection.rule_id or "",
            "name": detection.name,
            "description": detection.description or "",
            "severity": detection.severity,
            "tactics": json.dumps(detection.tactics),
            "techniques": json.dumps(detection.techniques),
            "mitre_techniques": json.dumps(detection.mitre_techniques),
            "author": detection.author or "",
            "created_date": detection.created_date or "",
            "last_modified": detection.last_modified or "",
            "version": detection.version or "",
            "enabled": detection.enabled,
            "query_frequency": detection.query_frequency or "",
            "query_period": detection.query_period or "",
            "source": detection.source,
            "type": "azure_sentinel_detection"
        }
    
    def _create_hunting_metadata(self, hunting_query: AzureSentinelHuntingQuery, file_path: Path) -> Dict[str, Any]:
        """Create metadata for hunting query ChromaDB storage.
        
        Args:
            hunting_query: AzureSentinelHuntingQuery object
            file_path: Path to the hunting query file
            
        Returns:
            Metadata dictionary
        """
        return {
            "file_path": str(file_path.relative_to(self.repo_path)),
            "query_id": hunting_query.query_id or "",
            "name": hunting_query.name,
            "description": hunting_query.description or "",
            "tactics": json.dumps(hunting_query.tactics),
            "techniques": json.dumps(hunting_query.techniques),
            "data_types": json.dumps(hunting_query.data_types),
            "mitre_techniques": json.dumps(hunting_query.mitre_techniques),
            "author": hunting_query.author or "",
            "created_date": hunting_query.created_date or "",
            "last_modified": hunting_query.last_modified or "",
            "version": hunting_query.version or "",
            "source": hunting_query.source,
            "type": "azure_sentinel_hunting"
        }
    
    def _validate_detection(self, detection: AzureSentinelDetection) -> Tuple[bool, List[str]]:
        """Validate a detection rule.
        
        Args:
            detection: AzureSentinelDetection object
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if not detection.name or detection.name.strip() == "":
            errors.append("Detection rule name is required")
        
        if not detection.query or detection.query.strip() == "":
            errors.append("Detection rule query is required")
        
        if detection.severity not in ["Low", "Medium", "High", "Critical"]:
            errors.append("Severity must be one of: Low, Medium, High, Critical")
        
        return len(errors) == 0, errors
    
    def _validate_hunting_query(self, hunting_query: AzureSentinelHuntingQuery) -> Tuple[bool, List[str]]:
        """Validate a hunting query.
        
        Args:
            hunting_query: AzureSentinelHuntingQuery object
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if not hunting_query.name or hunting_query.name.strip() == "":
            errors.append("Hunting query name is required")
        
        if not hunting_query.query or hunting_query.query.strip() == "":
            errors.append("Hunting query content is required")
        
        return len(errors) == 0, errors
    
    def _parse_detection_from_text(self, content: str, file_path: Path) -> Optional[AzureSentinelDetection]:
        """Parse detection rule from raw text content.
        
        Args:
            content: Raw text content
            file_path: Path to the file
            
        Returns:
            Parsed AzureSentinelDetection object or None
        """
        # This is a fallback parser for non-YAML detection files
        # Extract basic information using regex patterns
        
        name_match = re.search(r"(?:name|title):\s*(.+)", content, re.IGNORECASE)
        desc_match = re.search(r"description:\s*(.+)", content, re.IGNORECASE)
        query_match = re.search(r"query:\s*(.+)", content, re.IGNORECASE | re.DOTALL)
        
        if not name_match:
            return None
        
        detection = AzureSentinelDetection(
            name=name_match.group(1).strip(),
            description=desc_match.group(1).strip() if desc_match else "",
            query=query_match.group(1).strip() if query_match else "",
            severity="Medium"  # Default severity
        )
        
        # Extract MITRE techniques
        detection.mitre_techniques = self._extract_mitre_from_detection(detection)
        
        return detection
    
    def _parse_hunting_yaml(self, content: str, file_path: Path) -> Optional[AzureSentinelHuntingQuery]:
        """Parse hunting query from YAML content.
        
        Args:
            content: YAML content
            file_path: Path to the file
            
        Returns:
            Parsed AzureSentinelHuntingQuery object or None
        """
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return None
            
            hunting_query = AzureSentinelHuntingQuery(
                query_id=data.get("id"),
                name=data.get("name", file_path.stem),
                description=data.get("description", ""),
                query=data.get("query", ""),
                data_types=data.get("dataTypes") or [],
                tactics=data.get("tactics") or [],
                techniques=data.get("techniques") or [],
                required_data_connectors=data.get("requiredDataConnectors") or [],
                author=data.get("author"),
                created_date=data.get("createdDate"),
                last_modified=data.get("lastModified"),
                version=data.get("version")
            )
            
            # Extract MITRE techniques
            hunting_query.mitre_techniques = self._extract_mitre_from_hunting(hunting_query)
            
            return hunting_query
            
        except Exception as e:
            logger.error(f"Failed to parse hunting YAML {file_path}: {e}")
            return None


# Global Azure Sentinel ingestion instance
azure_sentinel_ingestion = AzureSentinelIngestion() 