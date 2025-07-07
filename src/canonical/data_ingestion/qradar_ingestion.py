"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Data ingestion script for QRadar correlation rules.
"""

import asyncio
import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from loguru import logger
from tqdm import tqdm

from ..core.config import settings
from ..core.models import QRadarRule
from ..services.chromadb import chromadb_service
from ..parsers.qradar import qradar_parser


class QRadarIngestion:
    """QRadar rules ingestion service."""
    
    def __init__(self):
        """Initialize the QRadar ingestion service."""
        self.collection_name = settings.qradar_collection
        self.supported_extensions = ['.txt', '.rule', '.xml', '.json', '.csv']
    
    async def ingest_from_directory(self, directory_path: str, force_refresh: bool = False) -> Dict[str, Any]:
        """Ingest QRadar rules from a directory.
        
        Args:
            directory_path: Path to directory containing QRadar rules
            force_refresh: Whether to force refresh the collection
            
        Returns:
            Ingestion statistics
        """
        logger.info(f"Starting QRadar rules ingestion from directory: {directory_path}")
        
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            # Clear collection if force refresh
            if force_refresh:
                logger.info("Force refresh enabled, clearing existing collection")
                await chromadb_service.delete_collection(self.collection_name)
                await chromadb_service.initialize()  # Recreate collection
            
            # Find all QRadar rule files
            rule_files = self._find_qradar_files(directory_path)
            logger.info(f"Found {len(rule_files)} QRadar rule files")
            
            if not rule_files:
                logger.warning("No QRadar rule files found")
                return {
                    "total_files": 0,
                    "total_processed": 0,
                    "successful": 0,
                    "failed": 0,
                    "collection": self.collection_name
                }
            
            # Process rules in batches
            batch_size = 50
            total_processed = 0
            total_successful = 0
            total_failed = 0
            
            for i in range(0, len(rule_files), batch_size):
                batch = rule_files[i:i + batch_size]
                batch_results = await self._process_batch(batch)
                
                total_processed += len(batch)
                total_successful += batch_results["successful"]
                total_failed += batch_results["failed"]
                
                logger.info(f"Processed {total_processed}/{len(rule_files)} QRadar rules")
            
            stats = {
                "total_files": len(rule_files),
                "total_processed": total_processed,
                "successful": total_successful,
                "failed": total_failed,
                "collection": self.collection_name
            }
            
            logger.info(f"QRadar ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"QRadar ingestion failed: {e}")
            raise
    
    async def ingest_from_file(self, file_path: str) -> Dict[str, Any]:
        """Ingest QRadar rules from a single file.
        
        Args:
            file_path: Path to the QRadar rules file
            
        Returns:
            Ingestion statistics
        """
        logger.info(f"Starting QRadar rules ingestion from file: {file_path}")
        
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"QRadar rules file not found: {file_path}")
            
            # Process the single file
            batch_results = await self._process_batch([file_path_obj])
            
            stats = {
                "total_files": 1,
                "total_processed": 1,
                "successful": batch_results["successful"],
                "failed": batch_results["failed"],
                "collection": self.collection_name
            }
            
            logger.info(f"QRadar file ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"QRadar file ingestion failed: {e}")
            raise
    
    async def ingest_from_text(self, rule_content: str, rule_name: str = "Manual Rule") -> Dict[str, Any]:
        """Ingest a QRadar rule from text content.
        
        Args:
            rule_content: QRadar rule content as text
            rule_name: Name for the rule
            
        Returns:
            Ingestion statistics
        """
        logger.info(f"Starting QRadar rule ingestion from text: {rule_name}")
        
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            # Parse the rule
            parsed_rule = qradar_parser.parse_rule(rule_content)
            
            # Override name if provided
            if rule_name != "Manual Rule":
                parsed_rule.name = rule_name
            
            # Validate rule
            is_valid, errors = qradar_parser.validate_rule(parsed_rule)
            if not is_valid:
                logger.error(f"Invalid QRadar rule: {errors}")
                return {
                    "total_files": 1,
                    "total_processed": 1,
                    "successful": 0,
                    "failed": 1,
                    "collection": self.collection_name,
                    "errors": errors
                }
            
            # Create rule summary for embedding
            rule_summary = qradar_parser.extract_rule_summary(parsed_rule)
            
            # Create metadata
            metadata = self._create_rule_metadata(parsed_rule, "manual_input")
            
            # Create document ID
            doc_id = f"qradar_manual_{rule_name.replace(' ', '_').lower()}"
            
            # Add to ChromaDB
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=[rule_summary],
                metadatas=[metadata],
                ids=[doc_id]
            )
            
            stats = {
                "total_files": 1,
                "total_processed": 1,
                "successful": 1,
                "failed": 0,
                "collection": self.collection_name
            }
            
            logger.info(f"QRadar text ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"QRadar text ingestion failed: {e}")
            raise
    
    def _find_qradar_files(self, directory_path: str) -> List[Path]:
        """Find all QRadar rule files in a directory.
        
        Args:
            directory_path: Path to the directory
            
        Returns:
            List of QRadar rule file paths
        """
        rule_files = []
        directory = Path(directory_path)
        
        if not directory.exists():
            logger.warning(f"Directory does not exist: {directory_path}")
            return rule_files
        
        # Look for files with supported extensions
        for extension in self.supported_extensions:
            rule_files.extend(directory.rglob(f"*{extension}"))
        
        # Also look for files without extensions that might contain rules
        for file_path in directory.rglob("*"):
            if file_path.is_file() and file_path.suffix == "":
                # Check if file contains QRadar rule patterns
                if self._is_qradar_rule_file(file_path):
                    rule_files.append(file_path)
        
        return sorted(rule_files)
    
    def _is_qradar_rule_file(self, file_path: Path) -> bool:
        """Check if a file contains QRadar rules.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file appears to contain QRadar rules
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000)  # Read first 1000 characters
            
            # Look for QRadar rule patterns
            qradar_patterns = [
                r"when\s+.+\s+(?:and|or)",
                r"(?:qid|category|sourceip|destinationip|username)\s*[=!<>]",
                r"(?:Rule Name|Rule Type|Description):",
                r"(?:Severity|Credibility|Relevance):\s*\d+",
                r"payload\s+(?:ilike|matches)",
                r"last\s+\d+\s+(?:minutes?|hours?|days?)",
                r"group\s+by\s+\w+",
                r"having\s+count\s*\(",
            ]
            
            for pattern in qradar_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception:
            return False
    
    async def _process_batch(self, rule_files: List[Path]) -> Dict[str, int]:
        """Process a batch of QRadar rule files.
        
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
                # Read and parse rules from file
                parsed_rules = self._parse_rule_file(rule_file)
                
                if not parsed_rules:
                    logger.warning(f"No valid rules found in file: {rule_file}")
                    failed += 1
                    continue
                
                # Process each rule in the file
                for i, rule in enumerate(parsed_rules):
                    try:
                        # Validate rule
                        is_valid, errors = qradar_parser.validate_rule(rule)
                        if not is_valid:
                            logger.warning(f"Invalid rule in {rule_file}: {errors}")
                            failed += 1
                            continue
                        
                        # Create rule summary for embedding
                        rule_summary = qradar_parser.extract_rule_summary(rule)
                        
                        # Create metadata
                        metadata = self._create_rule_metadata(rule, str(rule_file))
                        
                        # Create document ID
                        doc_id = f"qradar_{rule_file.stem}_{i}_{rule.rule_id or 'unknown'}"
                        
                        documents.append(rule_summary)
                        metadatas.append(metadata)
                        ids.append(doc_id)
                        
                        successful += 1
                        
                    except Exception as e:
                        logger.error(f"Failed to process rule {i} in {rule_file}: {e}")
                        failed += 1
                
            except Exception as e:
                logger.error(f"Failed to process file {rule_file}: {e}")
                failed += 1
        
        # Add to ChromaDB
        if documents:
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
        
        return {"successful": successful, "failed": failed}
    
    def _parse_rule_file(self, file_path: Path) -> List[QRadarRule]:
        """Parse QRadar rules from a file.
        
        Args:
            file_path: Path to the rule file
            
        Returns:
            List of parsed QRadar rules
        """
        rules = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check file extension and parse accordingly
            if file_path.suffix.lower() == '.json':
                rules = self._parse_json_rules(content)
            elif file_path.suffix.lower() == '.xml':
                rules = self._parse_xml_rules(content)
            elif file_path.suffix.lower() == '.csv':
                rules = self._parse_csv_rules(content)
            else:
                # Default text parsing
                rules = self._parse_text_rules(content)
            
        except Exception as e:
            logger.error(f"Failed to parse rule file {file_path}: {e}")
        
        return rules
    
    def _parse_json_rules(self, content: str) -> List[QRadarRule]:
        """Parse QRadar rules from JSON content.
        
        Args:
            content: JSON content
            
        Returns:
            List of parsed QRadar rules
        """
        rules = []
        
        try:
            data = json.loads(content)
            
            # Handle different JSON structures
            if isinstance(data, list):
                # Array of rules
                for rule_data in data:
                    rule = self._parse_json_rule(rule_data)
                    if rule:
                        rules.append(rule)
            elif isinstance(data, dict):
                if 'rules' in data:
                    # Rules in 'rules' key
                    for rule_data in data['rules']:
                        rule = self._parse_json_rule(rule_data)
                        if rule:
                            rules.append(rule)
                else:
                    # Single rule
                    rule = self._parse_json_rule(data)
                    if rule:
                        rules.append(rule)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
        
        return rules
    
    def _parse_json_rule(self, rule_data: Dict[str, Any]) -> Optional[QRadarRule]:
        """Parse a single QRadar rule from JSON data.
        
        Args:
            rule_data: JSON rule data
            
        Returns:
            Parsed QRadar rule or None
        """
        try:
            rule = QRadarRule(
                rule_id=rule_data.get("id") or rule_data.get("rule_id"),
                name=rule_data.get("name", "Unknown Rule"),
                description=rule_data.get("description"),
                rule_type=rule_data.get("rule_type", "EVENT"),
                enabled=rule_data.get("enabled", True),
                tests=rule_data.get("tests", []),
                actions=rule_data.get("actions", []),
                responses=rule_data.get("responses", []),
                groups=rule_data.get("groups", []),
                severity=rule_data.get("severity"),
                credibility=rule_data.get("credibility"),
                relevance=rule_data.get("relevance"),
                category=rule_data.get("category"),
                origin=rule_data.get("origin"),
                username=rule_data.get("username"),
                creation_date=rule_data.get("creation_date"),
                modification_date=rule_data.get("modification_date")
            )
            
            return rule
            
        except Exception as e:
            logger.error(f"Failed to parse JSON rule: {e}")
            return None
    
    def _parse_xml_rules(self, content: str) -> List[QRadarRule]:
        """Parse QRadar rules from XML content.
        
        Args:
            content: XML content
            
        Returns:
            List of parsed QRadar rules
        """
        rules = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            
            # Look for rule elements
            for rule_elem in root.findall(".//rule"):
                rule = self._parse_xml_rule(rule_elem)
                if rule:
                    rules.append(rule)
            
        except Exception as e:
            logger.error(f"Failed to parse XML rules: {e}")
        
        return rules
    
    def _parse_xml_rule(self, rule_elem) -> Optional[QRadarRule]:
        """Parse a single QRadar rule from XML element.
        
        Args:
            rule_elem: XML rule element
            
        Returns:
            Parsed QRadar rule or None
        """
        try:
            rule = QRadarRule(
                rule_id=rule_elem.get("id"),
                name=rule_elem.findtext("name", "Unknown Rule"),
                description=rule_elem.findtext("description"),
                rule_type=rule_elem.findtext("rule_type", "EVENT"),
                enabled=rule_elem.findtext("enabled", "true").lower() == "true",
                severity=self._safe_int(rule_elem.findtext("severity")),
                credibility=self._safe_int(rule_elem.findtext("credibility")),
                relevance=self._safe_int(rule_elem.findtext("relevance")),
                category=rule_elem.findtext("category"),
                origin=rule_elem.findtext("origin"),
                username=rule_elem.findtext("username"),
                creation_date=rule_elem.findtext("creation_date"),
                modification_date=rule_elem.findtext("modification_date")
            )
            
            return rule
            
        except Exception as e:
            logger.error(f"Failed to parse XML rule: {e}")
            return None
    
    def _parse_csv_rules(self, content: str) -> List[QRadarRule]:
        """Parse QRadar rules from CSV content.
        
        Args:
            content: CSV content
            
        Returns:
            List of parsed QRadar rules
        """
        rules = []
        
        try:
            import csv
            import io
            
            reader = csv.DictReader(io.StringIO(content))
            
            for row in reader:
                rule = QRadarRule(
                    rule_id=row.get("rule_id") or row.get("id"),
                    name=row.get("name", "Unknown Rule"),
                    description=row.get("description"),
                    rule_type=row.get("rule_type", "EVENT"),
                    enabled=row.get("enabled", "true").lower() == "true",
                    severity=self._safe_int(row.get("severity")),
                    credibility=self._safe_int(row.get("credibility")),
                    relevance=self._safe_int(row.get("relevance")),
                    category=row.get("category"),
                    origin=row.get("origin"),
                    username=row.get("username"),
                    creation_date=row.get("creation_date"),
                    modification_date=row.get("modification_date")
                )
                
                rules.append(rule)
            
        except Exception as e:
            logger.error(f"Failed to parse CSV rules: {e}")
        
        return rules
    
    def _parse_text_rules(self, content: str) -> List[QRadarRule]:
        """Parse QRadar rules from text content.
        
        Args:
            content: Text content
            
        Returns:
            List of parsed QRadar rules
        """
        rules = []
        
        # Split content into potential rule sections
        # Look for rule delimiters or parse as single rule
        rule_sections = self._split_rule_sections(content)
        
        for section in rule_sections:
            if section.strip():
                rule = qradar_parser.parse_rule(section)
                if rule and rule.name != "Parse Error":
                    rules.append(rule)
        
        return rules
    
    def _split_rule_sections(self, content: str) -> List[str]:
        """Split content into individual rule sections.
        
        Args:
            content: Raw content
            
        Returns:
            List of rule section strings
        """
        # Common rule delimiters
        delimiters = [
            r"(?:^|\n)Rule Name:",
            r"(?:^|\n)Rule ID:",
            r"(?:^|\n)---+",
            r"(?:^|\n)===+",
            r"(?:^|\n)Rule\s+\d+:",
        ]
        
        sections = [content]  # Start with full content
        
        for delimiter in delimiters:
            new_sections = []
            for section in sections:
                parts = re.split(delimiter, section, flags=re.MULTILINE)
                if len(parts) > 1:
                    # Keep the delimiter with the content
                    for i, part in enumerate(parts):
                        if i == 0 and part.strip():
                            new_sections.append(part)
                        elif i > 0:
                            # Add delimiter back
                            delimiter_match = re.search(delimiter, section)
                            if delimiter_match:
                                new_sections.append(delimiter_match.group(0) + part)
                            else:
                                new_sections.append(part)
                else:
                    new_sections.append(section)
            sections = new_sections
        
        return [s for s in sections if s.strip()]
    
    def _create_rule_metadata(self, rule: QRadarRule, file_path: str) -> Dict[str, Any]:
        """Create metadata for rule ChromaDB storage.
        
        Args:
            rule: QRadar rule object
            file_path: Path to the source file
            
        Returns:
            Metadata dictionary
        """
        return {
            "file_path": file_path,
            "rule_id": rule.rule_id or "",
            "name": rule.name,
            "description": rule.description or "",
            "rule_type": rule.rule_type,
            "enabled": rule.enabled,
            "severity": rule.severity or 0,
            "credibility": rule.credibility or 0,
            "relevance": rule.relevance or 0,
            "category": rule.category or "",
            "origin": rule.origin or "",
            "username": rule.username or "",
            "creation_date": rule.creation_date or "",
            "modification_date": rule.modification_date or "",
            "groups": json.dumps(rule.groups),
            "mitre_techniques": json.dumps(rule.mitre_techniques),
            "complexity": rule.complexity,
            "num_tests": len(rule.tests),
            "num_actions": len(rule.actions),
            "num_responses": len(rule.responses),
            "source": "QRadar",
            "type": "qradar_rule"
        }
    
    def _safe_int(self, value: Optional[str]) -> Optional[int]:
        """Safely convert string to int.
        
        Args:
            value: String value to convert
            
        Returns:
            Integer value or None
        """
        if value is None:
            return None
        
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    
    async def search_rules(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Search for QRadar rules.
        
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
        """Get a specific QRadar rule by ID.
        
        Args:
            rule_id: Rule ID to search for
            
        Returns:
            Rule data or None
        """
        results = await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=f"rule_id:{rule_id}",
            n_results=1,
            where={"rule_id": rule_id}
        )
        
        return results[0] if results else None
    
    async def get_rules_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get QRadar rules by category.
        
        Args:
            category: Rule category
            
        Returns:
            List of rules in the category
        """
        return await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=f"category:{category}",
            n_results=50,
            where={"category": category}
        )


# Global QRadar ingestion instance
qradar_ingestion = QRadarIngestion() 