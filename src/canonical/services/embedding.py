"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
OpenAI embedding service for text vectorization using text-embedding-3-large.
"""

import asyncio
from typing import List, Optional
import numpy as np
from loguru import logger

from ..core.config import settings


class EmbeddingService:
    """OpenAI embedding service using text-embedding-3-large."""
    
    def __init__(self, model_name: Optional[str] = None):
        """Initialize the OpenAI embedding service.
        
        Args:
            model_name: Name of the OpenAI embedding model to use
        """
        self.model_name = model_name or settings.embedding_model
        self.client = None
        self._initialized = False
        
        # Ensure we're using an OpenAI embedding model
        if not self.model_name.startswith('text-embedding-'):
            logger.warning(f"Model {self.model_name} doesn't appear to be an OpenAI embedding model. Using text-embedding-3-large instead.")
            self.model_name = "text-embedding-3-large"
        
    async def initialize(self) -> None:
        """Initialize the OpenAI embedding client."""
        if self._initialized:
            return
            
        try:
            from openai import AsyncOpenAI
            
            # Check if we should use Azure OpenAI or standard OpenAI
            if hasattr(settings, 'azure_openai_api_key') and settings.azure_openai_api_key:
                logger.info(f"Loading Azure OpenAI embedding model: {self.model_name}")
                # For Azure OpenAI, we need to use AsyncAzureOpenAI
                from openai import AsyncAzureOpenAI
                self.client = AsyncAzureOpenAI(
                    api_key=settings.azure_openai_api_key,
                    api_version=getattr(settings, 'azure_openai_api_version', '2024-06-01'),
                    azure_endpoint=getattr(settings, 'azure_openai_endpoint', '')
                )
            else:
                logger.info(f"Loading OpenAI embedding model: {self.model_name}")
                # Create OpenAI client
                self.client = AsyncOpenAI(
                    api_key=getattr(settings, 'openai_api_key', '')
                )
            
            self._initialized = True
            logger.info(f"OpenAI embedding model {self.model_name} loaded successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI embedding client: {e}")
            raise

    async def embed_text(self, text: str) -> List[float]:
        """Embed a single text string using OpenAI.
        
        Args:
            text: Text to embed
            
        Returns:
            List of embedding values (3072 dimensions for text-embedding-3-large)
        """
        if not self._initialized:
            await self.initialize()
            
        try:
            response = await self.client.embeddings.create(
                model=self.model_name,
                input=text
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"Failed to embed text with OpenAI: {e}")
            raise

    async def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple text strings using OpenAI.
        
        Args:
            texts: List of texts to embed
            
        Returns:
            List of embedding lists
        """
        if not self._initialized:
            await self.initialize()
            
        try:
            # OpenAI has batch limits, so we process in chunks
            batch_size = min(2048, len(texts))  # OpenAI's max batch size is 2048
            embeddings = []
            
            for i in range(0, len(texts), batch_size):
                batch = texts[i:i + batch_size]
                logger.debug(f"Processing OpenAI embedding batch {i//batch_size + 1}/{(len(texts) + batch_size - 1)//batch_size}")
                
                response = await self.client.embeddings.create(
                    model=self.model_name,
                    input=batch
                )
                batch_embeddings = [data.embedding for data in response.data]
                embeddings.extend(batch_embeddings)
            
            return embeddings
        except Exception as e:
            logger.error(f"Failed to embed texts with OpenAI: {e}")
            raise
    
    async def compute_similarity(self, text1: str, text2: str) -> float:
        """Compute cosine similarity between two texts.
        
        Args:
            text1: First text
            text2: Second text
            
        Returns:
            Cosine similarity score
        """
        embeddings = await self.embed_texts([text1, text2])
        emb1, emb2 = np.array(embeddings[0]), np.array(embeddings[1])
        
        # Compute cosine similarity
        similarity = np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2))
        return float(similarity)
    
    async def find_most_similar(self, query: str, candidates: List[str], top_k: int = 5) -> List[tuple]:
        """Find the most similar texts to a query.
        
        Args:
            query: Query text
            candidates: List of candidate texts
            top_k: Number of top results to return
            
        Returns:
            List of (text, similarity_score) tuples
        """
        if not candidates:
            return []
            
        # Embed query and candidates
        query_embedding = await self.embed_text(query)
        candidate_embeddings = await self.embed_texts(candidates)
        
        # Compute similarities
        similarities = []
        query_emb = np.array(query_embedding)
        
        for i, candidate_emb in enumerate(candidate_embeddings):
            cand_emb = np.array(candidate_emb)
            similarity = np.dot(query_emb, cand_emb) / (np.linalg.norm(query_emb) * np.linalg.norm(cand_emb))
            similarities.append((candidates[i], float(similarity)))
        
        # Sort by similarity and return top_k
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_k]
    
    def get_embedding_dimension(self) -> int:
        """Get the dimension of the embedding vectors.
        
        Returns:
            Embedding dimension (3072 for text-embedding-3-large)
        """
        if not self._initialized:
            raise RuntimeError("Embedding service not initialized")
        
        # Return dimensions for OpenAI models
        if 'text-embedding-3-large' in self.model_name:
            return 3072  # text-embedding-3-large: 3072 dimensions
        elif 'text-embedding-3-small' in self.model_name:
            return 1536  # text-embedding-3-small: 1536 dimensions
        elif 'text-embedding-ada-002' in self.model_name:
            return 1536  # text-embedding-ada-002: 1536 dimensions
        else:
            return 3072  # Default to text-embedding-3-large


# Global embedding service instance - lazy initialization
embedding_service = None

def get_embedding_service():
    """Get the embedding service instance, initializing if needed."""
    global embedding_service
    if embedding_service is None:
        embedding_service = EmbeddingService()
    return embedding_service 