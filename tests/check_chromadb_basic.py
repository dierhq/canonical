#!/usr/bin/env python3
"""
Basic check to see if ChromaDB collections are accessible
"""

import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "canonical" / "src"))

from canonical.services.chromadb import chromadb_service

async def check_chromadb_access():
    """Basic check of ChromaDB accessibility."""
    
    print("🔍 Basic ChromaDB Accessibility Check")
    print("=" * 50)
    
    try:
        await chromadb_service.initialize()
        print("✅ ChromaDB service initialized successfully")
        
        # Check if we can get the client
        client = chromadb_service.client
        print(f"✅ Client object: {type(client)}")
        
        # Try to list collections
        try:
            collections = client.list_collections()
            print(f"✅ Found {len(collections)} collections:")
            for collection in collections:
                print(f"   - {collection.name} (count: {collection.count()})")
        except Exception as e:
            print(f"❌ Error listing collections: {e}")
        
        # Try to get the azure_sentinel_detections collection directly
        try:
            collection = client.get_collection("azure_sentinel_detections")
            count = collection.count()
            print(f"✅ azure_sentinel_detections collection: {count} documents")
            
            # Try to peek at some documents
            if count > 0:
                print("🔍 Trying to peek at first few documents...")
                try:
                    # Use peek to get some documents without search
                    peek_result = collection.peek(limit=3)
                    print(f"✅ Peek successful! Got {len(peek_result.get('ids', []))} documents")
                    
                    # Show some IDs and document snippets
                    ids = peek_result.get('ids', [])
                    documents = peek_result.get('documents', [])
                    
                    for i, (doc_id, doc) in enumerate(zip(ids, documents)):
                        print(f"   Document {i+1}:")
                        print(f"     ID: {doc_id}")
                        print(f"     Content: {doc[:100] if doc else 'No content'}...")
                        
                except Exception as e:
                    print(f"❌ Error peeking at documents: {e}")
            else:
                print("⚠️  Collection is empty!")
                
        except Exception as e:
            print(f"❌ Error accessing azure_sentinel_detections collection: {e}")
        
        # Try a very simple search
        print("\n🔍 Testing basic search functionality...")
        try:
            # Try the simplest possible search
            results = await chromadb_service.search_similar(
                collection_name="azure_sentinel_detections",
                query="test",
                n_results=1
            )
            print(f"✅ Basic search returned {len(results)} results")
            if results:
                print(f"   First result ID: {results[0].get('id', 'No ID')}")
                print(f"   First result content: {results[0].get('document', 'No content')[:100]}...")
        except Exception as e:
            print(f"❌ Error in basic search: {e}")
            import traceback
            traceback.print_exc()
        
    except Exception as e:
        print(f"❌ Failed to initialize ChromaDB: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    import asyncio
    asyncio.run(check_chromadb_access()) 