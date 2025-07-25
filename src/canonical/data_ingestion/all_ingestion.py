"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Unified data ingestion script for all data sources.
"""

import asyncio
from typing import Dict, Any
from loguru import logger

from .mitre_ingestion import mitre_ingestion
from .car_ingestion import car_ingestion
from .atomic_ingestion import atomic_ingestion
from .azure_sentinel_ingestion import azure_sentinel_ingestion
from .sigma_ingestion import sigma_ingestion
from .azure_docs_ingestion import ingest_azure_docs
from .qradar_docs_ingestion import qradar_docs_ingestion


async def ingest_all_data(force_refresh: bool = False) -> Dict[str, Any]:
    """Ingest all data sources.
    
    Args:
        force_refresh: Whether to force refresh all data
        
    Returns:
        Combined ingestion statistics
    """
    logger.info("Starting unified data ingestion for all sources")
    
    results = {}
    
    try:
        # Ingest MITRE ATT&CK data
        logger.info("Starting MITRE ATT&CK ingestion...")
        mitre_stats = await mitre_ingestion.ingest_mitre_data(force_refresh)
        results["mitre_attack"] = mitre_stats
        
        # Ingest MITRE CAR data
        logger.info("Starting MITRE CAR ingestion...")
        car_stats = await car_ingestion.ingest_car_data(force_refresh)
        results["mitre_car"] = car_stats
        
        # Ingest Atomic Red Team data
        logger.info("Starting Atomic Red Team ingestion...")
        atomic_stats = await atomic_ingestion.ingest_atomic_data(force_refresh)
        results["atomic_red_team"] = atomic_stats
        
        # Ingest Sigma Rules data
        logger.info("Starting Sigma Rules ingestion...")
        sigma_stats = await sigma_ingestion.ingest_sigma_rules(force_refresh)
        results["sigma_rules"] = sigma_stats
        
        # Ingest Azure Sentinel data
        logger.info("Starting Azure Sentinel ingestion...")
        azure_stats = await azure_sentinel_ingestion.ingest_all(force_refresh)
        results["azure_sentinel"] = azure_stats
        
        # Ingest Azure Sentinel Documentation
        logger.info("Starting Azure Sentinel documentation ingestion...")
        azure_docs_success = await ingest_azure_docs()
        results["azure_docs"] = {"success": azure_docs_success}
        
        # Ingest QRadar Documentation
        logger.info("Starting QRadar documentation ingestion...")
        qradar_docs_stats = await qradar_docs_ingestion.ingest_qradar_blog_docs(force_refresh)
        results["qradar_docs"] = qradar_docs_stats
        
        logger.info("All data ingestion completed successfully")
        logger.info(f"Final statistics: {results}")
        
        return results
        
    except Exception as e:
        logger.error(f"Unified data ingestion failed: {e}")
        raise


if __name__ == "__main__":
    # Run the ingestion
    asyncio.run(ingest_all_data(force_refresh=True)) 