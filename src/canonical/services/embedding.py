"""
BGE embedding service for text vectorization.
"""

import asyncio
from typing import List, Union, Optional
import numpy as np
from sentence_transformers import SentenceTransformer
from loguru import logger

from ..core.config import settings


class EmbeddingService:
    """BGE embedding service for text vectorization."""
    
    def __init__(self, model_name: Optional[str] = None, device: Optional[str] = None):
        """Initialize the embedding service.
        
        Args:
            model_name: Name of the embedding model to use
            device: Device to run the model on ('cpu', 'cuda', 'mps')
        """
        self.model_name = model_name or settings.embedding_model
        self.device = device or settings.embedding_device
        self.model = None
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the embedding model."""
        if self._initialized:
            return
            
        try:
            logger.info(f"Loading embedding model: {self.model_name}")
            self.model = SentenceTransformer(
                self.model_name,
                device=self.device
            )
            self._initialized = True
            logger.info(f"Embedding model loaded successfully on {self.device}")
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            raise
    
    async def embed_text(self, text: str) -> List[float]:
        """Embed a single text string.
        
        Args:
            text: Text to embed
            
        Returns:
            List of embedding values
        """
        if not self._initialized:
            await self.initialize()
            
        try:
            # Run embedding in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            embedding = await loop.run_in_executor(
                None,
                lambda: self.model.encode(text, convert_to_tensor=False)
            )
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Failed to embed text: {e}")
            raise
    
    async def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple text strings.
        
        Args:
            texts: List of texts to embed
            
        Returns:
            List of embedding lists
        """
        if not self._initialized:
            await self.initialize()
            
        try:
            # Process in batches to manage memory
            batch_size = settings.embedding_batch_size
            embeddings = []
            
            for i in range(0, len(texts), batch_size):
                batch = texts[i:i + batch_size]
                logger.debug(f"Processing embedding batch {i//batch_size + 1}/{(len(texts) + batch_size - 1)//batch_size}")
                
                # Run embedding in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                batch_embeddings = await loop.run_in_executor(
                    None,
                    lambda: self.model.encode(batch, convert_to_tensor=False)
                )
                embeddings.extend([emb.tolist() for emb in batch_embeddings])
            
            return embeddings
        except Exception as e:
            logger.error(f"Failed to embed texts: {e}")
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
            Embedding dimension
        """
        if not self._initialized:
            raise RuntimeError("Embedding service not initialized")
        return self.model.get_sentence_embedding_dimension()


# Global embedding service instance
embedding_service = EmbeddingService() 