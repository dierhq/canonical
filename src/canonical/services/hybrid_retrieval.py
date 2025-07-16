"""
Hybrid retrieval service that combines semantic and keyword-based search.
"""

from typing import Dict, Any, List, Optional
from loguru import logger

from .chromadb import chromadb_service
from .embedding import embedding_service


class HybridRetrievalService:
    """Hybrid retrieval service combining semantic and keyword search."""
    
    def __init__(self):
        self.chromadb_service = chromadb_service
        self.embedding_service = embedding_service
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the hybrid retrieval service."""
        if not self._initialized:
            await self.chromadb_service.initialize()
            await self.embedding_service.initialize()
            self._initialized = True
    
    async def retrieve_context_for_conversion(
        self,
        rule_content: str,
        source_format: str,
        target_format: str,
        max_results: int = 5
    ) -> Dict[str, Any]:
        """Retrieve relevant context for rule conversion."""
        await self.initialize()
        
        try:
            # Search for similar rules and examples
            semantic_results = await self._semantic_search(rule_content, max_results)
            
            # Search for format-specific examples
            format_results = await self._format_specific_search(source_format, target_format, max_results)
            
            # Combine and deduplicate results
            combined_results = self._combine_results(semantic_results, format_results)
            
            return {
                "success": True,
                "context": combined_results,
                "semantic_results": len(semantic_results),
                "format_results": len(format_results),
                "total_results": len(combined_results)
            }
            
        except Exception as e:
            logger.error(f"Error retrieving context for conversion: {e}")
            return {
                "success": False,
                "context": [],
                "error": str(e)
            }
    
    async def _semantic_search(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        """Perform semantic search using embeddings."""
        try:
            # Generate embedding for the query
            query_embedding = await self.embedding_service.embed_text(query)
            
            # Search in ChromaDB
            results = await self.chromadb_service.search_similar(
                query_embedding=query_embedding,
                n_results=max_results
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Error in semantic search: {e}")
            return []
    
    async def _format_specific_search(
        self,
        source_format: str,
        target_format: str,
        max_results: int
    ) -> List[Dict[str, Any]]:
        """Search for format-specific examples."""
        try:
            # Search for examples of the target format
            format_query = f"{target_format} examples rules"
            format_results = await self._semantic_search(format_query, max_results)
            
            return format_results
            
        except Exception as e:
            logger.error(f"Error in format-specific search: {e}")
            return []
    
    def _combine_results(
        self,
        semantic_results: List[Dict[str, Any]],
        format_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Combine and deduplicate search results."""
        combined = []
        seen_ids = set()
        
        # Add semantic results first (higher priority)
        for result in semantic_results:
            result_id = result.get("id", "")
            if result_id and result_id not in seen_ids:
                combined.append(result)
                seen_ids.add(result_id)
        
        # Add format results that weren't already included
        for result in format_results:
            result_id = result.get("id", "")
            if result_id and result_id not in seen_ids:
                combined.append(result)
                seen_ids.add(result_id)
        
        return combined


# Create singleton instance
hybrid_retrieval_service = HybridRetrievalService() 