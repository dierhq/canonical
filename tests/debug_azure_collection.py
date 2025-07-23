#!/usr/bin/env python3
"""
Debug script to see what's in the Azure Sentinel collection
"""

import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "canonical" / "src"))

from canonical.services.chromadb import chromadb_service

async def debug_azure_collection():
    """Debug the Azure Sentinel collection content."""
    
    print("🔍 Debugging Azure Sentinel Collection")
    print("=" * 50)
    
    await chromadb_service.initialize()
    
    # Test different search terms
    search_terms = [
        "DNS query",
        "DNS",
        "base64",
        "domain name",
        "network traffic",
        "malicious domain",
        "suspicious DNS",
        "data exfiltration"
    ]
    
    for term in search_terms:
        print(f"\n🔍 Searching for: '{term}'")
        try:
            results = await chromadb_service.search_similar(
                collection_name="azure_sentinel_detections",
                query=term,
                n_results=3
            )
            
            print(f"   Found {len(results)} results")
            for i, result in enumerate(results):
                doc = result.get('document', '')[:200] + "..." if len(result.get('document', '')) > 200 else result.get('document', '')
                print(f"   {i+1}. {doc}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Try to get some random samples
    print(f"\n📋 Random samples from collection:")
    try:
        # Search with a very generic term to get some results
        results = await chromadb_service.search_similar(
            collection_name="azure_sentinel_detections",
            query="security event detection rule",
            n_results=5
        )
        
        for i, result in enumerate(results):
            doc = result.get('document', '')
            print(f"\nSample {i+1}:")
            print(f"ID: {result.get('id', 'N/A')}")
            print(f"Content: {doc[:300]}...")
            
            # Look for table names
            tables = ["DnsEvents", "SecurityEvent", "DeviceNetworkInfo", "CommonSecurityLog"]
            found_tables = [table for table in tables if table in doc]
            if found_tables:
                print(f"Tables found: {found_tables}")
            
    except Exception as e:
        print(f"❌ Error getting samples: {e}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(debug_azure_collection()) 