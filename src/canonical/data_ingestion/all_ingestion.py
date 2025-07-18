"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Unified data ingestion script for all data sources with GPU acceleration support.
"""

import asyncio
import os
import sys
from typing import Dict, Any
from loguru import logger

from .mitre_ingestion import mitre_ingestion
from .car_ingestion import car_ingestion
from .atomic_ingestion import atomic_ingestion
from .azure_sentinel_ingestion import azure_sentinel_ingestion
from .sigma_ingestion import sigma_ingestion
from .azure_docs_ingestion import ingest_azure_docs
from .qradar_docs_ingestion import qradar_docs_ingestion


def setup_gpu_acceleration():
    """Setup GPU acceleration environment variables if CUDA is available."""
    try:
        import torch
        if torch.cuda.is_available():
            # Set GPU acceleration environment variables
            os.environ['QWEN_DEVICE'] = 'cuda'
            os.environ['EMBEDDING_DEVICE'] = 'cuda'
            os.environ['CUDA_VISIBLE_DEVICES'] = '0'
            logger.info(f"🚀 GPU acceleration enabled - CUDA devices: {torch.cuda.device_count()}")
            logger.info(f"   - QWEN_DEVICE: {os.environ.get('QWEN_DEVICE')}")
            logger.info(f"   - EMBEDDING_DEVICE: {os.environ.get('EMBEDDING_DEVICE')}")
            logger.info(f"   - CUDA_VISIBLE_DEVICES: {os.environ.get('CUDA_VISIBLE_DEVICES')}")
            return True
        else:
            logger.warning("CUDA not available, falling back to CPU")
            return False
    except ImportError:
        logger.warning("PyTorch not available, falling back to CPU")
        return False


async def ingest_all_data(force_refresh: bool = False, enable_gpu: bool = True) -> Dict[str, Any]:
    """Ingest all data sources with GPU acceleration support.
    
    Args:
        force_refresh: Whether to force refresh all data
        enable_gpu: Whether to enable GPU acceleration (default: True)
        
    Returns:
        Combined ingestion statistics
    """
    logger.info("🚀 Starting unified data ingestion for all sources")
    
    # Setup GPU acceleration if requested and available
    gpu_enabled = False
    if enable_gpu:
        gpu_enabled = setup_gpu_acceleration()
    
    results = {}
    
    try:
        # Ingest MITRE ATT&CK data
        logger.info("📥 Starting MITRE ATT&CK ingestion...")
        try:
            mitre_stats = await mitre_ingestion.ingest_mitre_data(force_refresh)
            results["mitre_attack"] = mitre_stats
            logger.info(f"✅ MITRE ATT&CK ingestion completed: {mitre_stats.get('total_processed', 0)} items")
        except Exception as e:
            logger.error(f"❌ MITRE ATT&CK ingestion failed: {e}")
            results["mitre_attack"] = {"error": str(e), "success": False}
        
        # Ingest MITRE CAR data
        logger.info("📥 Starting MITRE CAR ingestion...")
        try:
            car_stats = await car_ingestion.ingest_car_data(force_refresh)
            results["mitre_car"] = car_stats
            logger.info(f"✅ MITRE CAR ingestion completed: {car_stats.get('successful', 0)} analytics")
        except Exception as e:
            logger.error(f"❌ MITRE CAR ingestion failed: {e}")
            results["mitre_car"] = {"error": str(e), "success": False}
        
        # Ingest Atomic Red Team data
        logger.info("📥 Starting Atomic Red Team ingestion...")
        try:
            atomic_stats = await atomic_ingestion.ingest_atomic_data(force_refresh)
            results["atomic_red_team"] = atomic_stats
            logger.info(f"✅ Atomic Red Team ingestion completed: {atomic_stats.get('successful', 0)} tests")
        except Exception as e:
            logger.error(f"❌ Atomic Red Team ingestion failed: {e}")
            results["atomic_red_team"] = {"error": str(e), "success": False}
        
        # Ingest Sigma Rules data
        logger.info("📥 Starting Sigma Rules ingestion...")
        try:
            sigma_stats = await sigma_ingestion.ingest_sigma_rules(force_refresh)
            results["sigma_rules"] = sigma_stats
            logger.info(f"✅ Sigma Rules ingestion completed: {sigma_stats.get('successful', 0)} rules")
        except Exception as e:
            logger.error(f"❌ Sigma Rules ingestion failed: {e}")
            results["sigma_rules"] = {"error": str(e), "success": False}
        
        # Ingest Azure Sentinel data
        logger.info("📥 Starting Azure Sentinel ingestion...")
        try:
            azure_stats = await azure_sentinel_ingestion.ingest_all(force_refresh)
            results["azure_sentinel"] = azure_stats
            total_azure = azure_stats.get('total_successful', 0)
            logger.info(f"✅ Azure Sentinel ingestion completed: {total_azure} items")
        except Exception as e:
            logger.error(f"❌ Azure Sentinel ingestion failed: {e}")
            results["azure_sentinel"] = {"error": str(e), "success": False}
        
        # Ingest Azure Sentinel Documentation
        logger.info("📥 Starting Azure Sentinel documentation ingestion...")
        try:
            azure_docs_success = await ingest_azure_docs()
            results["azure_docs"] = {"success": azure_docs_success}
            logger.info(f"✅ Azure Sentinel documentation ingestion: {'completed' if azure_docs_success else 'failed'}")
        except Exception as e:
            logger.error(f"❌ Azure Sentinel documentation ingestion failed: {e}")
            results["azure_docs"] = {"error": str(e), "success": False}
        
        # Ingest QRadar Documentation
        logger.info("📥 Starting QRadar documentation ingestion...")
        try:
            qradar_docs_stats = await qradar_docs_ingestion.ingest_qradar_docs(force_refresh)
            results["qradar_docs"] = qradar_docs_stats
            logger.info(f"✅ QRadar documentation ingestion completed: {qradar_docs_stats.get('successful', 0)} items")
        except Exception as e:
            logger.error(f"❌ QRadar documentation ingestion failed: {e}")
            results["qradar_docs"] = {"error": str(e), "success": False}
        
        # Calculate summary statistics
        total_successful = 0
        total_failed = 0
        total_items = 0
        
        for source, stats in results.items():
            if isinstance(stats, dict):
                if "error" in stats:
                    total_failed += 1
                else:
                    total_successful += 1
                    # Count items based on different stat structures
                    if "total_processed" in stats:
                        total_items += stats["total_processed"]
                    elif "successful" in stats:
                        total_items += stats["successful"]
                    elif "total_successful" in stats:
                        total_items += stats["total_successful"]
        
        # Add summary to results
        results["_summary"] = {
            "total_sources": len(results) - 1,  # Exclude summary itself
            "successful_sources": total_successful,
            "failed_sources": total_failed,
            "total_items_ingested": total_items,
            "gpu_enabled": gpu_enabled
        }
        
        logger.info("🎉 All data ingestion completed successfully")
        logger.info(f"📊 Final statistics: {results['_summary']}")
        
        return results
        
    except Exception as e:
        logger.error(f"❌ Unified data ingestion failed: {e}")
        raise


if __name__ == "__main__":
    # Run the ingestion
    asyncio.run(ingest_all_data(force_refresh=True, enable_gpu=True))
