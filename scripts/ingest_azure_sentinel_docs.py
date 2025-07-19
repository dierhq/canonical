#!/usr/bin/env python3
"""
Azure Sentinel Documentation Ingestion

This script downloads and processes the comprehensive Azure Sentinel documentation
from Microsoft Learn (3000+ pages) and ingests it into ChromaDB collections.
"""

import asyncio
import requests
import fitz  # PyMuPDF
import json
import os
import sys
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import time
from urllib.parse import urlparse

# Add the canonical package to the path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from canonical.services.chromadb import ChromaDBService
from canonical.services.embedding import EmbeddingService

@dataclass
class DocumentSection:
    """A section of Azure Sentinel documentation"""
    id: str
    title: str
    content: str
    page_number: int
    section_type: str  # 'overview', 'tutorial', 'reference', 'guide', etc.
    keywords: List[str]
    url_source: str
    metadata: Dict[str, Any]

class AzureSentinelDocsIngester:
    """Ingest Azure Sentinel documentation from Microsoft Learn PDF"""
    
    def __init__(self):
        self.docs_url = "https://learn.microsoft.com/pdf?url=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Fazure%2Fsentinel%2Ftoc.json"
        self.pdf_path = Path("data/azure_sentinel_docs.pdf")
        self.chunk_size = 1000  # Characters per chunk for better embeddings
        self.overlap_size = 200  # Overlap between chunks
        
    async def ingest_all(self) -> bool:
        """Download and ingest all Azure Sentinel documentation"""
        try:
            print("🚀 Starting Azure Sentinel documentation ingestion...")
            
            # Initialize services
            embedding_service = EmbeddingService()
            await embedding_service.initialize()
            
            chromadb_service = ChromaDBService()
            await chromadb_service.initialize()
            
            # Download PDF if not exists
            if not await self._download_pdf():
                return False
            
            # Process PDF and extract sections
            print("📖 Processing PDF documentation...")
            sections = await self._process_pdf()
            
            if not sections:
                print("❌ No sections extracted from PDF")
                return False
            
            print(f"📝 Extracted {len(sections)} documentation sections")
            
            # Store in ChromaDB
            await self._store_sections(sections, chromadb_service, embedding_service)
            
            print(f"✅ Successfully ingested {len(sections)} Azure Sentinel documentation sections!")
            return True
            
        except Exception as e:
            print(f"❌ Documentation ingestion failed: {e}")
            return False
    
    async def _download_pdf(self) -> bool:
        """Download the Azure Sentinel PDF documentation"""
        try:
            if self.pdf_path.exists():
                file_size = self.pdf_path.stat().st_size
                if file_size > 1000000:  # 1MB minimum
                    print(f"📄 PDF already exists ({file_size:,} bytes), skipping download")
                    return True
                else:
                    print("🗑️ Removing incomplete PDF file")
                    self.pdf_path.unlink()
            
            print("📥 Downloading Azure Sentinel documentation PDF...")
            print(f"🔗 Source: {self.docs_url}")
            
            # Create data directory
            self.pdf_path.parent.mkdir(exist_ok=True)
            
            # Download with streaming to handle large file
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(self.docs_url, headers=headers, stream=True, timeout=60)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            print(f"📊 PDF size: {total_size:,} bytes")
            
            downloaded = 0
            with open(self.pdf_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # Progress indicator
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\r📥 Download progress: {progress:.1f}%", end='', flush=True)
            
            print(f"\n✅ PDF downloaded successfully: {downloaded:,} bytes")
            return True
            
        except Exception as e:
            print(f"❌ Failed to download PDF: {e}")
            return False
    
    async def _process_pdf(self) -> List[DocumentSection]:
        """Process the PDF and extract structured sections"""
        sections = []
        
        try:
            print("📖 Opening PDF document...")
            doc = fitz.open(str(self.pdf_path))
            total_pages = len(doc)
            print(f"📄 Processing {total_pages} pages...")
            
            current_section = None
            section_content = []
            
            for page_num in range(total_pages):
                if page_num % 100 == 0:
                    print(f"📄 Processing page {page_num + 1}/{total_pages}")
                
                page = doc[page_num]
                text = page.get_text()
                
                # Skip mostly empty pages
                if len(text.strip()) < 50:
                    continue
                
                # Process page content
                page_sections = await self._extract_sections_from_page(
                    text, page_num + 1
                )
                sections.extend(page_sections)
            
            doc.close()
            
            # Post-process sections for better chunking
            sections = await self._optimize_sections(sections)
            
            print(f"✅ Extracted {len(sections)} sections from {total_pages} pages")
            return sections
            
        except Exception as e:
            print(f"❌ Error processing PDF: {e}")
            return []
    
    async def _extract_sections_from_page(self, text: str, page_num: int) -> List[DocumentSection]:
        """Extract logical sections from a page of text"""
        sections = []
        
        try:
            # Clean up text
            text = re.sub(r'\s+', ' ', text).strip()
            
            # Split into chunks for better embedding quality
            chunks = self._create_text_chunks(text)
            
            for i, chunk in enumerate(chunks):
                if len(chunk.strip()) < 100:  # Skip very short chunks
                    continue
                
                # Detect section type and title
                section_type = self._detect_section_type(chunk)
                title = self._extract_title(chunk, page_num, i)
                keywords = self._extract_keywords(chunk)
                
                section = DocumentSection(
                    id=self._generate_section_id(page_num, i, chunk),
                    title=title,
                    content=chunk.strip(),
                    page_number=page_num,
                    section_type=section_type,
                    keywords=keywords,
                    url_source=self.docs_url,
                    metadata={
                        'chunk_index': i,
                        'chunk_count': len(chunks),
                        'source': 'Azure Sentinel Microsoft Learn',
                        'document_type': 'documentation',
                        'language': 'en'
                    }
                )
                
                sections.append(section)
            
            return sections
            
        except Exception as e:
            print(f"⚠️ Error processing page {page_num}: {e}")
            return []
    
    def _create_text_chunks(self, text: str) -> List[str]:
        """Create overlapping text chunks for better context preservation"""
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + self.chunk_size
            
            # Try to break at sentence boundary
            if end < len(text):
                # Look for sentence endings near the chunk boundary
                for i in range(end - 100, min(end + 100, len(text))):
                    if text[i:i+2] in ['. ', '.\n', '!\n', '?\n']:
                        end = i + 1
                        break
            
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            
            # Move start position with overlap
            start = max(start + self.chunk_size - self.overlap_size, end)
            
            if start >= len(text):
                break
        
        return chunks
    
    def _detect_section_type(self, text: str) -> str:
        """Detect the type of documentation section"""
        text_lower = text.lower()
        
        # Detection patterns for different section types
        if any(word in text_lower for word in ['tutorial', 'step-by-step', 'walkthrough']):
            return 'tutorial'
        elif any(word in text_lower for word in ['reference', 'api', 'function', 'cmdlet']):
            return 'reference'
        elif any(word in text_lower for word in ['overview', 'introduction', 'what is']):
            return 'overview'
        elif any(word in text_lower for word in ['configure', 'setup', 'install']):
            return 'configuration'
        elif any(word in text_lower for word in ['troubleshoot', 'problem', 'error']):
            return 'troubleshooting'
        elif any(word in text_lower for word in ['query', 'kql', 'kusto']):
            return 'query_guide'
        elif any(word in text_lower for word in ['rule', 'detection', 'alert']):
            return 'detection_guide'
        elif any(word in text_lower for word in ['workbook', 'dashboard', 'visualization']):
            return 'analytics'
        elif any(word in text_lower for word in ['connector', 'data source', 'integration']):
            return 'data_connector'
        elif any(word in text_lower for word in ['hunting', 'investigation', 'threat']):
            return 'threat_hunting'
        else:
            return 'general'
    
    def _extract_title(self, text: str, page_num: int, chunk_index: int) -> str:
        """Extract or generate a meaningful title for the section"""
        lines = text.split('\n')
        
        # Look for heading-like patterns
        for line in lines[:5]:  # Check first few lines
            line = line.strip()
            if len(line) > 10 and len(line) < 100:
                # Check if it looks like a heading
                if (line.isupper() or 
                    line.startswith('#') or 
                    any(word in line.lower() for word in ['azure sentinel', 'microsoft sentinel'])):
                    return line
        
        # Extract first meaningful sentence
        sentences = re.split(r'[.!?]+', text)
        for sentence in sentences[:3]:
            sentence = sentence.strip()
            if len(sentence) > 20 and len(sentence) < 150:
                return sentence
        
        # Fallback to page-based title
        return f"Azure Sentinel Documentation - Page {page_num} Section {chunk_index + 1}"
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract relevant keywords from the text"""
        keywords = set()
        text_lower = text.lower()
        
        # Azure Sentinel specific terms
        sentinel_terms = [
            'azure sentinel', 'microsoft sentinel', 'siem', 'soar', 
            'kql', 'kusto', 'analytics rule', 'workbook', 'playbook',
            'connector', 'data source', 'hunting', 'investigation',
            'incident', 'alert', 'detection', 'threat intelligence',
            'log analytics', 'workspace', 'security', 'monitoring'
        ]
        
        for term in sentinel_terms:
            if term in text_lower:
                keywords.add(term)
        
        # Extract capitalized words (likely important terms)
        capitalized_words = re.findall(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b', text)
        for word in capitalized_words[:10]:  # Limit to avoid noise
            if len(word) > 3:
                keywords.add(word.lower())
        
        return list(keywords)[:20]  # Limit keywords
    
    def _generate_section_id(self, page_num: int, chunk_index: int, content: str) -> str:
        """Generate a unique ID for the section"""
        content_hash = hashlib.md5(content.encode()).hexdigest()[:8]
        return f"azure_sentinel_docs_p{page_num:04d}_c{chunk_index:03d}_{content_hash}"
    
    async def _optimize_sections(self, sections: List[DocumentSection]) -> List[DocumentSection]:
        """Optimize sections by merging very short ones and splitting very long ones"""
        optimized = []
        
        for section in sections:
            # Split very long sections
            if len(section.content) > self.chunk_size * 2:
                sub_chunks = self._create_text_chunks(section.content)
                for i, chunk in enumerate(sub_chunks):
                    if len(chunk.strip()) > 100:
                        sub_section = DocumentSection(
                            id=f"{section.id}_sub{i}",
                            title=f"{section.title} (Part {i+1})",
                            content=chunk.strip(),
                            page_number=section.page_number,
                            section_type=section.section_type,
                            keywords=section.keywords,
                            url_source=section.url_source,
                            metadata={**section.metadata, 'sub_section': i}
                        )
                        optimized.append(sub_section)
            else:
                optimized.append(section)
        
        return optimized
    
    async def _store_sections(self, sections: List[DocumentSection], 
                             chromadb_service: ChromaDBService, 
                             embedding_service: EmbeddingService):
        """Store documentation sections in ChromaDB"""
        
        # Group sections by type for organized storage
        sections_by_type = {}
        for section in sections:
            section_type = section.section_type
            if section_type not in sections_by_type:
                sections_by_type[section_type] = []
            sections_by_type[section_type].append(section)
        
        print(f"📊 Section distribution:")
        for section_type, type_sections in sections_by_type.items():
            print(f"  • {section_type}: {len(type_sections)} sections")
        
        # Store all sections in main collection
        await self._store_section_batch(
            sections, "azure_sentinel_docs", chromadb_service
        )
        
        # Store specialized collections for key section types
        important_types = ['query_guide', 'detection_guide', 'reference', 'tutorial']
        for section_type in important_types:
            if section_type in sections_by_type:
                collection_name = f"azure_sentinel_docs_{section_type}"
                await self._store_section_batch(
                    sections_by_type[section_type], collection_name, chromadb_service
                )
    
    async def _store_section_batch(self, sections: List[DocumentSection], 
                                  collection_name: str, 
                                  chromadb_service: ChromaDBService):
        """Store a batch of sections in ChromaDB"""
        if not sections:
            return
        
        print(f"💾 Storing {len(sections)} sections in '{collection_name}'...")
        
        documents = []
        metadatas = []
        ids = []
        
        for section in sections:
            # Create rich document text for embedding
            doc_text = f"""
            Title: {section.title}
            Section Type: {section.section_type}
            Page: {section.page_number}
            Keywords: {', '.join(section.keywords)}
            
            Content:
            {section.content}
            """
            
            documents.append(doc_text.strip())
            
            metadatas.append({
                'id': section.id,
                'title': section.title,
                'page_number': section.page_number,
                'section_type': section.section_type,
                'keywords': json.dumps(section.keywords),
                'url_source': section.url_source,
                'content': section.content,
                'source': 'Azure Sentinel Documentation',
                'document_type': 'microsoft_learn_docs',
                **section.metadata
            })
            
            ids.append(section.id)
        
        # Store in ChromaDB (embeddings generated internally)
        try:
            await chromadb_service.add_documents(
                collection_name=collection_name,
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            print(f"✅ Stored {len(sections)} sections in '{collection_name}'")
        except Exception as e:
            print(f"❌ Error storing sections in '{collection_name}': {e}")

async def main():
    """Main documentation ingestion function"""
    print("🎯 Azure Sentinel Documentation Ingestion Starting...")
    print("📚 Target: 3000+ page Microsoft Learn documentation")
    
    ingester = AzureSentinelDocsIngester()
    success = await ingester.ingest_all()
    
    if success:
        print("🎉 Azure Sentinel documentation ingestion completed successfully!")
        return 0
    else:
        print("❌ Azure Sentinel documentation ingestion failed!")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 