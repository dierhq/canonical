"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
ChromaDB service for managing vector collections.
"""

import asyncio
import os
from typing import List, Dict, Any, Optional, Tuple
import chromadb
from chromadb.config import Settings as ChromaSettings
from loguru import logger

from ..core.config import settings
from ..services.embedding import embedding_service


class ChromaDBService:
    """ChromaDB service for managing vector collections."""
    
    def __init__(self):
        """Initialize the ChromaDB service."""
        self.client = None
        self.collections = {}
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize ChromaDB client and collections."""
        if self._initialized:
            return
            
        try:
            logger.info("Initializing ChromaDB client")
            
            # Initialize ChromaDB client with error recovery
            try:
                self.client = chromadb.PersistentClient(
                    path=settings.chromadb_path,
                    settings=ChromaSettings(
                        anonymized_telemetry=False,
                        allow_reset=True,
                        persist_directory=settings.chromadb_path
                    )
                )
            except Exception as persist_error:
                logger.warning(f"Persistent client failed: {persist_error}, trying alternative path")
                import tempfile
                alt_path = os.path.join(tempfile.gettempdir(), "chromadb_canonical")
                os.makedirs(alt_path, exist_ok=True)
                self.client = chromadb.PersistentClient(
                    path=alt_path,
                    settings=ChromaSettings(
                        anonymized_telemetry=False,
                        allow_reset=True
                    )
                )
            
            # Initialize embedding service
            await embedding_service.initialize()
            
            # Create or get collections
            await self._setup_collections()
            
            self._initialized = True
            logger.info("ChromaDB service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB service: {e}")
            raise
    
    async def _setup_collections(self) -> None:
        """Setup all required collections."""
        collection_configs = [
            {
                "name": settings.sigma_collection,
                "description": "Sigma rules from SigmaHQ repository"
            },
            {
                "name": settings.mitre_collection,
                "description": "MITRE ATT&CK techniques, groups, and software"
            },
            {
                "name": settings.car_collection,
                "description": "MITRE Cyber Analytics Repository (CAR)"
            },
            {
                "name": settings.atomic_collection,
                "description": "Atomic Red Team tests"
            },
            {
                "name": settings.azure_sentinel_detections_collection,
                "description": "Azure Sentinel detection rules"
            },
            {
                "name": settings.azure_sentinel_hunting_collection,
                "description": "Azure Sentinel hunting queries"
            },
            {
                "name": settings.qradar_collection,
                "description": "QRadar rules and correlation rules"
            },
            {
                "name": settings.qradar_docs_collection,
                "description": "QRadar documentation and knowledge base"
            },
            {
                "name": settings.ecs_fields_collection,
                "description": "ECS (Elastic Common Schema) field reference for EQL/KibanaQL"
            },
            {
                "name": "environment_schemas",
                "description": "Environment schemas for schema-aware rule conversion"
            }
        ]
        
        for config in collection_configs:
            try:
                collection = self.client.get_or_create_collection(
                    name=config["name"],
                    metadata={"description": config["description"]}
                )
                self.collections[config["name"]] = collection
                logger.info(f"Collection '{config['name']}' ready")
            except Exception as e:
                logger.error(f"Failed to setup collection '{config['name']}': {e}")
                raise
    
    async def ensure_collection(self, collection_name: str, description: str = None) -> None:
        """Ensure a collection exists, creating it if necessary.
        
        Args:
            collection_name: Name of the collection
            description: Optional description for the collection
        """
        if not self._initialized:
            await self.initialize()
        
        if collection_name not in self.collections:
            try:
                collection = self.client.get_or_create_collection(
                    name=collection_name,
                    metadata={"description": description or f"Dynamic collection: {collection_name}"}
                )
                self.collections[collection_name] = collection
                logger.info(f"Collection '{collection_name}' created/ensured")
            except Exception as e:
                logger.error(f"Failed to create collection '{collection_name}': {e}")
                raise

    async def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: List[Dict[str, Any]],
        ids: Optional[List[str]] = None
    ) -> None:
        """Add documents to a collection.
        
        Args:
            collection_name: Name of the collection
            documents: List of document texts
            metadatas: List of metadata dictionaries
            ids: Optional list of document IDs
        """
        if not self._initialized:
            await self.initialize()
        
        # Ensure collection exists
        await self.ensure_collection(collection_name)
        
        if collection_name not in self.collections:
            raise ValueError(f"Collection '{collection_name}' could not be created")
        
        try:
            # Generate embeddings
            logger.info(f"Generating embeddings for {len(documents)} documents")
            embeddings = await embedding_service.embed_texts(documents)
            
            # Generate IDs if not provided
            if ids is None:
                ids = [f"doc_{i}" for i in range(len(documents))]
            
            # Add to collection
            collection = self.collections[collection_name]
            collection.add(
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas,
                ids=ids
            )
            
            logger.info(f"Added {len(documents)} documents to '{collection_name}'")
        except Exception as e:
            logger.error(f"Failed to add documents to '{collection_name}': {e}")
            raise
    
    async def search_similar(
        self,
        collection_name: str,
        query: str,
        n_results: int = 10,
        where: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Search for similar documents in a collection.
        
        Args:
            collection_name: Name of the collection
            query: Query text
            n_results: Number of results to return
            where: Optional metadata filter
            
        Returns:
            List of similar documents with metadata
        """
        if not self._initialized:
            await self.initialize()
        
        if collection_name not in self.collections:
            raise ValueError(f"Collection '{collection_name}' not found")
        
        try:
            # Generate query embedding
            query_embedding = await embedding_service.embed_text(query)
            
            # Search collection
            collection = self.collections[collection_name]
            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                where=where,
                include=["documents", "metadatas", "distances"]
            )
            
            # Format results
            formatted_results = []
            for i in range(len(results["documents"][0])):
                formatted_results.append({
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i],
                    "similarity": 1 - results["distances"][0][i]  # Convert distance to similarity
                })
            
            return formatted_results
        except Exception as e:
            logger.error(f"Failed to search collection '{collection_name}': {e}")
            raise
    
    async def get_collection_stats(self, collection_name: str) -> Dict[str, Any]:
        """Get statistics for a collection.
        
        Args:
            collection_name: Name of the collection
            
        Returns:
            Collection statistics
        """
        if not self._initialized:
            await self.initialize()
        
        if collection_name not in self.collections:
            raise ValueError(f"Collection '{collection_name}' not found")
        
        try:
            collection = self.collections[collection_name]
            count = collection.count()
            metadata = collection.metadata
            
            return {
                "name": collection_name,
                "count": count,
                "metadata": metadata
            }
        except Exception as e:
            logger.error(f"Failed to get stats for collection '{collection_name}': {e}")
            raise
    
    async def delete_collection(self, collection_name: str) -> None:
        """Delete a collection.
        
        Args:
            collection_name: Name of the collection to delete
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            self.client.delete_collection(collection_name)
            if collection_name in self.collections:
                del self.collections[collection_name]
            logger.info(f"Deleted collection '{collection_name}'")
        except Exception as e:
            logger.error(f"Failed to delete collection '{collection_name}': {e}")
            raise
    
    async def update_document(
        self,
        collection_name: str,
        document_id: str,
        document: str,
        metadata: Dict[str, Any]
    ) -> None:
        """Update a document in a collection.
        
        Args:
            collection_name: Name of the collection
            document_id: ID of the document to update
            document: Updated document text
            metadata: Updated metadata
        """
        if not self._initialized:
            await self.initialize()
        
        if collection_name not in self.collections:
            raise ValueError(f"Collection '{collection_name}' not found")
        
        try:
            # Generate embedding for updated document
            embedding = await embedding_service.embed_text(document)
            
            # Update document
            collection = self.collections[collection_name]
            collection.update(
                ids=[document_id],
                documents=[document],
                embeddings=[embedding],
                metadatas=[metadata]
            )
            
            logger.info(f"Updated document '{document_id}' in '{collection_name}'")
        except Exception as e:
            logger.error(f"Failed to update document '{document_id}' in '{collection_name}': {e}")
            raise
    
    async def find_mitre_techniques(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find MITRE ATT&CK techniques related to a query.
        
        Args:
            query: Query text
            n_results: Number of results to return
            
        Returns:
            List of related MITRE techniques
        """
        return await self.search_similar(
            collection_name=settings.mitre_collection,
            query=query,
            n_results=n_results,
            where={"type": "technique"}
        )
    
    async def find_similar_sigma_rules(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find similar Sigma rules to a query.
        
        Args:
            query: Query text (rule content or description)
            n_results: Number of results to return
            
        Returns:
            List of similar Sigma rules
        """
        return await self.search_similar(
            collection_name=settings.sigma_collection,
            query=query,
            n_results=n_results
        )
    
    async def find_atomic_tests(self, technique_id: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find Atomic Red Team tests for a MITRE technique.
        
        Args:
            technique_id: MITRE technique ID (e.g., "T1059.001")
            n_results: Number of results to return
            
        Returns:
            List of related Atomic tests
        """
        return await self.search_similar(
            collection_name=settings.atomic_collection,
            query=f"technique {technique_id}",
            n_results=n_results,
            where={"technique": technique_id}
        )
    
    async def find_car_analytics(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find MITRE CAR analytics related to a query.
        
        Args:
            query: Query text
            n_results: Number of results to return
            
        Returns:
            List of related CAR analytics
        """
        return await self.search_similar(
            collection_name=settings.car_collection,
            query=query,
            n_results=n_results
        )
    
    async def find_azure_sentinel_detections(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find Azure Sentinel detection rules related to a query.
        
        Args:
            query: Query text
            n_results: Number of results to return
            
        Returns:
            List of related Azure Sentinel detection rules
        """
        return await self.search_similar(
            collection_name=settings.azure_sentinel_detections_collection,
            query=query,
            n_results=n_results
        )
    
    async def find_azure_sentinel_hunting_queries(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find Azure Sentinel hunting queries related to a query.
        
        Args:
            query: Query text
            n_results: Number of results to return
            
        Returns:
            List of related Azure Sentinel hunting queries
        """
        return await self.search_similar(
            collection_name=settings.azure_sentinel_hunting_collection,
            query=query,
            n_results=n_results
        )
    
    async def find_qradar_rules(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find QRadar rules related to a query.
        
        Args:
            query: Query text
            n_results: Number of results to return
            
        Returns:
            List of related QRadar rules
        """
        return await self.search_similar(
            collection_name=settings.qradar_collection,
            query=query,
            n_results=n_results
        )


# Global ChromaDB service instance
chromadb_service = ChromaDBService() 