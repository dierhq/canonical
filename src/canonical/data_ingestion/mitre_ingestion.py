"""
Data ingestion script for MITRE ATT&CK framework.
"""

import asyncio
import json
import requests
from typing import List, Dict, Any, Optional
from pathlib import Path
from loguru import logger

from ..core.config import settings
from ..services.chromadb import chromadb_service


class MitreIngestion:
    """MITRE ATT&CK framework ingestion."""
    
    def __init__(self):
        """Initialize the MITRE ingestion service."""
        self.data_url = settings.mitre_attack_url
        self.collection_name = settings.mitre_collection
        self.cache_path = settings.cache_dir / "mitre_attack.json"
    
    async def ingest_mitre_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Ingest MITRE ATT&CK data.
        
        Args:
            force_refresh: Whether to force refresh the data
            
        Returns:
            Ingestion statistics
        """
        logger.info("Starting MITRE ATT&CK ingestion")
        
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            # Download or load cached data
            mitre_data = await self._get_mitre_data(force_refresh)
            
            # Process different object types
            stats = {
                "techniques": 0,
                "tactics": 0,
                "groups": 0,
                "software": 0,
                "mitigations": 0,
                "total_processed": 0
            }
            
            # Process all objects in the STIX bundle
            for obj in mitre_data.get("objects", []):
                obj_type = obj.get("type")
                
                if obj_type == "attack-pattern":
                    await self._process_technique(obj)
                    stats["techniques"] += 1
                elif obj_type == "x-mitre-tactic":
                    await self._process_tactic(obj)
                    stats["tactics"] += 1
                elif obj_type == "intrusion-set":
                    await self._process_group(obj)
                    stats["groups"] += 1
                elif obj_type == "malware" or obj_type == "tool":
                    await self._process_software(obj)
                    stats["software"] += 1
                elif obj_type == "course-of-action":
                    await self._process_mitigation(obj)
                    stats["mitigations"] += 1
                
                stats["total_processed"] += 1
            
            logger.info(f"MITRE ATT&CK ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"MITRE ATT&CK ingestion failed: {e}")
            raise
    
    async def _get_mitre_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Download or load cached MITRE ATT&CK data.
        
        Args:
            force_refresh: Whether to force download fresh data
            
        Returns:
            MITRE ATT&CK data
        """
        if not force_refresh and self.cache_path.exists():
            logger.info("Loading cached MITRE ATT&CK data")
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        logger.info(f"Downloading MITRE ATT&CK data from {self.data_url}")
        response = requests.get(self.data_url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        # Cache the data
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        logger.info("MITRE ATT&CK data downloaded and cached")
        return data
    
    async def _process_technique(self, technique: Dict[str, Any]) -> None:
        """Process a MITRE technique.
        
        Args:
            technique: Technique object
        """
        try:
            # Extract technique ID
            external_refs = technique.get("external_references", [])
            technique_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            
            if not technique_id:
                return
            
            # Extract kill chain phases (tactics)
            tactics = []
            for phase in technique.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name"))
            
            # Create document text for embedding
            document_text = f"""
            MITRE ATT&CK Technique: {technique_id}
            Name: {technique.get('name', '')}
            Description: {technique.get('description', '')}
            Tactics: {', '.join(tactics)}
            Platforms: {', '.join(technique.get('x_mitre_platforms', []))}
            Data Sources: {', '.join(technique.get('x_mitre_data_sources', []))}
            """.strip()
            
            # Create metadata
            metadata = {
                "technique_id": technique_id,
                "name": technique.get("name", ""),
                "description": technique.get("description", ""),
                "tactics": json.dumps(tactics),
                "platforms": json.dumps(technique.get("x_mitre_platforms", [])),
                "data_sources": json.dumps(technique.get("x_mitre_data_sources", [])),
                "type": "technique",
                "stix_id": technique.get("id", ""),
                "created": technique.get("created", ""),
                "modified": technique.get("modified", "")
            }
            
            # Add to ChromaDB
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=[document_text],
                metadatas=[metadata],
                ids=[f"technique_{technique_id}"]
            )
            
        except Exception as e:
            logger.error(f"Failed to process technique: {e}")
    
    async def _process_tactic(self, tactic: Dict[str, Any]) -> None:
        """Process a MITRE tactic.
        
        Args:
            tactic: Tactic object
        """
        try:
            # Extract tactic ID
            external_refs = tactic.get("external_references", [])
            tactic_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id")
                    break
            
            if not tactic_id:
                return
            
            # Create document text for embedding
            document_text = f"""
            MITRE ATT&CK Tactic: {tactic_id}
            Name: {tactic.get('name', '')}
            Description: {tactic.get('description', '')}
            Short Name: {tactic.get('x_mitre_shortname', '')}
            """.strip()
            
            # Create metadata
            metadata = {
                "tactic_id": tactic_id,
                "name": tactic.get("name", ""),
                "description": tactic.get("description", ""),
                "short_name": tactic.get("x_mitre_shortname", ""),
                "type": "tactic",
                "stix_id": tactic.get("id", ""),
                "created": tactic.get("created", ""),
                "modified": tactic.get("modified", "")
            }
            
            # Add to ChromaDB
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=[document_text],
                metadatas=[metadata],
                ids=[f"tactic_{tactic_id}"]
            )
            
        except Exception as e:
            logger.error(f"Failed to process tactic: {e}")
    
    async def _process_group(self, group: Dict[str, Any]) -> None:
        """Process a MITRE group.
        
        Args:
            group: Group object
        """
        try:
            # Extract group ID
            external_refs = group.get("external_references", [])
            group_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    group_id = ref.get("external_id")
                    break
            
            if not group_id:
                return
            
            # Create document text for embedding
            aliases = group.get("aliases", [])
            document_text = f"""
            MITRE ATT&CK Group: {group_id}
            Name: {group.get('name', '')}
            Description: {group.get('description', '')}
            Aliases: {', '.join(aliases)}
            """.strip()
            
            # Create metadata
            metadata = {
                "group_id": group_id,
                "name": group.get("name", ""),
                "description": group.get("description", ""),
                "aliases": json.dumps(aliases),
                "type": "group",
                "stix_id": group.get("id", ""),
                "created": group.get("created", ""),
                "modified": group.get("modified", "")
            }
            
            # Add to ChromaDB
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=[document_text],
                metadatas=[metadata],
                ids=[f"group_{group_id}"]
            )
            
        except Exception as e:
            logger.error(f"Failed to process group: {e}")
    
    async def _process_software(self, software: Dict[str, Any]) -> None:
        """Process MITRE software (malware/tools).
        
        Args:
            software: Software object
        """
        try:
            # Extract software ID
            external_refs = software.get("external_references", [])
            software_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    software_id = ref.get("external_id")
                    break
            
            if not software_id:
                return
            
            # Create document text for embedding
            labels = software.get("labels", [])
            document_text = f"""
            MITRE ATT&CK Software: {software_id}
            Name: {software.get('name', '')}
            Description: {software.get('description', '')}
            Type: {software.get('type', '')}
            Labels: {', '.join(labels)}
            Platforms: {', '.join(software.get('x_mitre_platforms', []))}
            """.strip()
            
            # Create metadata
            metadata = {
                "software_id": software_id,
                "name": software.get("name", ""),
                "description": software.get("description", ""),
                "software_type": software.get("type", ""),
                "labels": json.dumps(labels),
                "platforms": json.dumps(software.get("x_mitre_platforms", [])),
                "type": "software",
                "stix_id": software.get("id", ""),
                "created": software.get("created", ""),
                "modified": software.get("modified", "")
            }
            
            # Add to ChromaDB
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=[document_text],
                metadatas=[metadata],
                ids=[f"software_{software_id}"]
            )
            
        except Exception as e:
            logger.error(f"Failed to process software: {e}")
    
    async def _process_mitigation(self, mitigation: Dict[str, Any]) -> None:
        """Process a MITRE mitigation.
        
        Args:
            mitigation: Mitigation object
        """
        try:
            # Extract mitigation ID
            external_refs = mitigation.get("external_references", [])
            mitigation_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitigation_id = ref.get("external_id")
                    break
            
            if not mitigation_id:
                return
            
            # Create document text for embedding
            document_text = f"""
            MITRE ATT&CK Mitigation: {mitigation_id}
            Name: {mitigation.get('name', '')}
            Description: {mitigation.get('description', '')}
            """.strip()
            
            # Create metadata
            metadata = {
                "mitigation_id": mitigation_id,
                "name": mitigation.get("name", ""),
                "description": mitigation.get("description", ""),
                "type": "mitigation",
                "stix_id": mitigation.get("id", ""),
                "created": mitigation.get("created", ""),
                "modified": mitigation.get("modified", "")
            }
            
            # Add to ChromaDB
            await chromadb_service.add_documents(
                collection_name=self.collection_name,
                documents=[document_text],
                metadatas=[metadata],
                ids=[f"mitigation_{mitigation_id}"]
            )
            
        except Exception as e:
            logger.error(f"Failed to process mitigation: {e}")
    
    async def search_techniques(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Search for MITRE techniques.
        
        Args:
            query: Search query
            n_results: Number of results to return
            
        Returns:
            List of matching techniques
        """
        return await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=query,
            n_results=n_results,
            where={"type": "technique"}
        )
    
    async def get_technique_by_id(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific technique by ID.
        
        Args:
            technique_id: Technique ID to search for
            
        Returns:
            Technique data if found
        """
        results = await chromadb_service.search_similar(
            collection_name=self.collection_name,
            query=f"technique {technique_id}",
            n_results=1,
            where={"technique_id": technique_id}
        )
        
        return results[0] if results else None


# Global ingestion instance
mitre_ingestion = MitreIngestion() 