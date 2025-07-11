import requests
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any
import json
import hashlib
from datetime import datetime

# PDF processing imports
try:
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False

try:
    from mistralai.client import MistralClient
    HAS_MISTRAL = True
except ImportError:
    HAS_MISTRAL = False

from ..services.embedding import embedding_service
from ..services.chromadb import chromadb_service
from ..core.config import settings

logger = logging.getLogger(__name__)

class AzureDocsIngestion:
    def __init__(self):
        self.pdf_url = "https://learn.microsoft.com/pdf?url=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Fazure%2Fsentinel%2Ftoc.json"
        self.pdf_path = Path("data/azure_sentinel_docs.pdf")
        self.collection_name = "azure_sentinel_docs"
        self.chunk_size = 1000  # characters per chunk
        self.chunk_overlap = 200  # overlap between chunks
        
    async def download_pdf(self) -> bool:
        """Download the Azure Sentinel documentation PDF"""
        try:
            logger.info(f"Downloading PDF from {self.pdf_url}")
            
            # Create data directory if it doesn't exist
            self.pdf_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Download with progress tracking
            response = requests.get(self.pdf_url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(self.pdf_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            if downloaded % (1024 * 1024) == 0:  # Log every MB
                                logger.info(f"Downloaded {downloaded // (1024*1024)}MB / {total_size // (1024*1024)}MB ({progress:.1f}%)")
            
            logger.info(f"PDF downloaded successfully: {self.pdf_path} ({downloaded // (1024*1024)}MB)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download PDF: {e}")
            return False
    
    def extract_text_pymupdf(self) -> str:
        """Extract text using PyMuPDF"""
        if not HAS_PYMUPDF:
            raise ImportError("PyMuPDF not installed. Install with: pip install PyMuPDF")
        
        logger.info("Extracting text using PyMuPDF...")
        doc = fitz.open(self.pdf_path)
        full_text = ""
        
        for page_num in range(len(doc)):
            page = doc[page_num]
            text = page.get_text()
            full_text += f"\n--- Page {page_num + 1} ---\n{text}"
            
            if page_num % 100 == 0:
                logger.info(f"Processed {page_num + 1}/{len(doc)} pages")
        
        doc.close()
        logger.info(f"Text extraction complete: {len(full_text)} characters")
        return full_text
    
    async def extract_text_mistral(self) -> str:
        """Extract text using Mistral AI OCR (if available)"""
        if not HAS_MISTRAL:
            raise ImportError("Mistral AI client not installed")
        
        logger.info("Extracting text using Mistral AI OCR...")
        # Implementation would depend on Mistral's PDF processing API
        # For now, fall back to PyMuPDF
        return self.extract_text_pymupdf()
    
    def chunk_text(self, text: str) -> List[Dict[str, Any]]:
        """Split text into overlapping chunks"""
        logger.info(f"Chunking text into {self.chunk_size} character chunks...")
        
        chunks = []
        start = 0
        chunk_id = 0
        
        while start < len(text):
            end = start + self.chunk_size
            chunk_text = text[start:end]
            
            # Try to break at sentence boundaries
            if end < len(text) and '.' in chunk_text[-100:]:
                last_period = chunk_text.rfind('.')
                if last_period > len(chunk_text) - 200:
                    end = start + last_period + 1
                    chunk_text = text[start:end]
            
            # Create chunk metadata
            chunk = {
                "id": f"azure_docs_chunk_{chunk_id}",
                "text": chunk_text.strip(),
                "source": "Azure Sentinel Documentation",
                "chunk_index": chunk_id,
                "char_start": start,
                "char_end": end,
                "created_at": datetime.now().isoformat(),
                "content_hash": hashlib.md5(chunk_text.encode()).hexdigest()
            }
            
            chunks.append(chunk)
            chunk_id += 1
            
            # Move start position with overlap
            start = end - self.chunk_overlap
            
            if chunk_id % 100 == 0:
                logger.info(f"Created {chunk_id} chunks...")
        
        logger.info(f"Text chunking complete: {len(chunks)} chunks created")
        return chunks
    
    async def ingest_chunks(self, chunks: List[Dict[str, Any]]) -> bool:
        """Ingest chunks into ChromaDB"""
        try:
            logger.info(f"Ingesting {len(chunks)} chunks into ChromaDB...")
            
            # Initialize services
            await embedding_service.initialize()
            await chromadb_service.initialize()
            
            # Create or get collection directly from ChromaDB client
            collection = chromadb_service.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": "Azure Sentinel Documentation"}
            )
            
            # Process chunks in batches
            batch_size = 50
            for i in range(0, len(chunks), batch_size):
                batch = chunks[i:i + batch_size]
                
                # Prepare batch data
                texts = [chunk["text"] for chunk in batch]
                metadatas = [{k: v for k, v in chunk.items() if k != "text"} for chunk in batch]
                ids = [chunk["id"] for chunk in batch]
                
                # Generate embeddings
                embeddings = await embedding_service.embed_texts(texts)
                
                # Add to ChromaDB
                collection.add(
                    embeddings=embeddings,
                    documents=texts,
                    metadatas=metadatas,
                    ids=ids
                )
                
                logger.info(f"Ingested batch {i//batch_size + 1}/{(len(chunks) + batch_size - 1)//batch_size}")
            
            logger.info("✅ Azure Sentinel documentation ingestion complete!")
            return True
            
        except Exception as e:
            logger.error(f"Failed to ingest chunks: {e}")
            return False
    
    async def run(self) -> bool:
        """Run the complete ingestion process"""
        try:
            logger.info("🚀 Starting Azure Sentinel documentation ingestion...")
            
            # Step 1: Download PDF
            if not self.pdf_path.exists():
                if not await self.download_pdf():
                    return False
            else:
                logger.info("PDF already exists, skipping download")
            
            # Step 2: Extract text
            if HAS_MISTRAL and hasattr(settings, 'mistral_api_key'):
                text = await self.extract_text_mistral()
            else:
                text = self.extract_text_pymupdf()
            
            # Step 3: Chunk text
            chunks = self.chunk_text(text)
            
            # Step 4: Ingest into ChromaDB
            success = await self.ingest_chunks(chunks)
            
            # Step 5: Cleanup
            if success:
                logger.info("🧹 Cleaning up temporary files...")
                # Optionally remove PDF to save space
                # self.pdf_path.unlink()
            
            return success
            
        except Exception as e:
            logger.error(f"Ingestion failed: {e}")
            return False

async def ingest_azure_docs():
    """Main entry point for Azure Sentinel documentation ingestion"""
    ingestion = AzureDocsIngestion()
    return await ingestion.run()

if __name__ == "__main__":
    asyncio.run(ingest_azure_docs()) 