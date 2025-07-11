#!/usr/bin/env python3
"""
Simple script to run Azure Sentinel documentation ingestion in RunPod
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, '/workspace/canonical/src')

# Set environment variables
os.environ['PYTHONPATH'] = '/workspace/canonical/src'
os.environ['QWEN_DEVICE'] = 'cuda'
os.environ['EMBEDDING_DEVICE'] = 'cuda'
os.environ['CUDA_VISIBLE_DEVICES'] = '0'

async def main():
    """Run Azure docs ingestion"""
    try:
        # Import and run
        from canonical.data_ingestion.azure_docs_ingestion import ingest_azure_docs
        
        print("🚀 Starting Azure Sentinel documentation ingestion...")
        success = await ingest_azure_docs()
        
        if success:
            print("✅ Azure Sentinel documentation ingestion completed successfully!")
        else:
            print("❌ Azure Sentinel documentation ingestion failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 