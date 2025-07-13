"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Main FastAPI application for the Canonical SIEM rule converter.
"""

import asyncio
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from ..core.config import settings
from ..core.models import (
    ConversionRequest, 
    ConversionResponse, 
    SourceFormat, 
    TargetFormat
)
from ..core.converter import rule_converter


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Canonical SIEM Rule Converter API")
    try:
        await rule_converter.initialize()
        logger.info("API startup completed successfully")
    except Exception as e:
        logger.error(f"Failed to initialize API: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Canonical SIEM Rule Converter API")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Intelligent SIEM rule converter that transforms security rules between different formats",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Welcome to Canonical SIEM Rule Converter",
        "version": settings.app_version,
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        stats = await rule_converter.get_conversion_stats()
        return {
            "status": "healthy",
            "initialized": stats["initialized"],
            "collections": stats.get("collections", {}),
            "version": settings.app_version
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "version": settings.app_version
            }
        )


@app.post("/convert", response_model=ConversionResponse)
async def convert_rule(request: ConversionRequest):
    """Convert a rule from source format to target format."""
    try:
        logger.info(f"Received conversion request: {request.source_format} -> {request.target_format}")
        
        response = await rule_converter.convert_rule(
            source_rule=request.source_rule,
            source_format=request.source_format,
            target_format=request.target_format,
            context=request.context
        )
        
        return response
    except Exception as e:
        logger.error(f"Conversion API error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/sigma/kustoql", response_model=ConversionResponse)
async def convert_sigma_to_kustoql(request: Dict[str, Any]):
    """Convert Sigma rule to KustoQL."""
    try:
        sigma_rule = request.get("rule")
        if not sigma_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_sigma_to_kustoql(sigma_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Sigma to KustoQL conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/sigma/kibanaql", response_model=ConversionResponse)
async def convert_sigma_to_kibanaql(request: Dict[str, Any]):
    """Convert Sigma rule to Kibana Query Language."""
    try:
        sigma_rule = request.get("rule")
        if not sigma_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_sigma_to_kibanaql(sigma_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Sigma to KibanaQL conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/sigma/eql", response_model=ConversionResponse)
async def convert_sigma_to_eql(request: Dict[str, Any]):
    """Convert Sigma rule to Event Query Language."""
    try:
        sigma_rule = request.get("rule")
        if not sigma_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_sigma_to_eql(sigma_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Sigma to EQL conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/sigma/qradar", response_model=ConversionResponse)
async def convert_sigma_to_qradar(request: Dict[str, Any]):
    """Convert Sigma rule to QRadar AQL."""
    try:
        sigma_rule = request.get("rule")
        if not sigma_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_sigma_to_qradar(sigma_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Sigma to QRadar conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/sigma/spl", response_model=ConversionResponse)
async def convert_sigma_to_spl(request: Dict[str, Any]):
    """Convert Sigma rule to Splunk Processing Language."""
    try:
        sigma_rule = request.get("rule")
        if not sigma_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_sigma_to_spl(sigma_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Sigma to SPL conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/qradar/kustoql", response_model=ConversionResponse)
async def convert_qradar_to_kustoql(request: Dict[str, Any]):
    """Convert QRadar rule to KustoQL (Azure Sentinel)."""
    try:
        qradar_rule = request.get("rule")
        if not qradar_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_qradar_to_kustoql(qradar_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"QRadar to KustoQL conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/kibanaql/kustoql", response_model=ConversionResponse)
async def convert_kibanaql_to_kustoql(request: Dict[str, Any]):
    """Convert KibanaQL rule to KustoQL (Azure Sentinel)."""
    try:
        kibanaql_rule = request.get("rule")
        if not kibanaql_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_kibanaql_to_kustoql(kibanaql_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"KibanaQL to KustoQL conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/kibanaql/kibanaql", response_model=ConversionResponse)
async def convert_kibanaql_to_kibanaql(request: Dict[str, Any]):
    """Convert KibanaQL rule to KibanaQL (validation/normalization)."""
    try:
        kibanaql_rule = request.get("rule")
        if not kibanaql_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_kibanaql_to_kibanaql(kibanaql_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"KibanaQL to KibanaQL conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/kibanaql/eql", response_model=ConversionResponse)
async def convert_kibanaql_to_eql(request: Dict[str, Any]):
    """Convert KibanaQL rule to EQL (Event Query Language)."""
    try:
        kibanaql_rule = request.get("rule")
        if not kibanaql_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_kibanaql_to_eql(kibanaql_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"KibanaQL to EQL conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/kibanaql/qradar", response_model=ConversionResponse)
async def convert_kibanaql_to_qradar(request: Dict[str, Any]):
    """Convert KibanaQL rule to QRadar AQL."""
    try:
        kibanaql_rule = request.get("rule")
        if not kibanaql_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_kibanaql_to_qradar(kibanaql_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"KibanaQL to QRadar conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/kibanaql/spl", response_model=ConversionResponse)
async def convert_kibanaql_to_spl(request: Dict[str, Any]):
    """Convert KibanaQL rule to Splunk SPL."""
    try:
        kibanaql_rule = request.get("rule")
        if not kibanaql_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_kibanaql_to_spl(kibanaql_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"KibanaQL to SPL conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/kibanaql/sigma", response_model=ConversionResponse)
async def convert_kibanaql_to_sigma(request: Dict[str, Any]):
    """Convert KibanaQL rule to Sigma."""
    try:
        kibanaql_rule = request.get("rule")
        if not kibanaql_rule:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        response = await rule_converter.convert_kibanaql_to_sigma(kibanaql_rule)
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"KibanaQL to Sigma conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Conversion failed: {str(e)}"
        )


@app.post("/convert/batch")
async def batch_convert_rules(request: Dict[str, Any]):
    """Convert multiple rules in batch."""
    try:
        rules = request.get("rules", [])
        target_format = request.get("target_format")
        max_concurrent = request.get("max_concurrent", 5)
        
        if not rules:
            raise HTTPException(status_code=400, detail="Missing 'rules' field")
        
        if not target_format:
            raise HTTPException(status_code=400, detail="Missing 'target_format' field")
        
        # Validate target format
        try:
            target_format_enum = TargetFormat(target_format)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid target format: {target_format}"
            )
        
        responses = await rule_converter.batch_convert(
            rules=rules,
            target_format=target_format_enum,
            max_concurrent=max_concurrent
        )
        
        return {
            "results": responses,
            "total": len(responses),
            "successful": sum(1 for r in responses if r.success),
            "failed": sum(1 for r in responses if not r.success)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch conversion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Batch conversion failed: {str(e)}"
        )


@app.post("/validate")
async def validate_rule(request: Dict[str, Any]):
    """Validate a rule without converting it."""
    try:
        rule_content = request.get("rule")
        source_format = request.get("source_format", "sigma")
        
        if not rule_content:
            raise HTTPException(status_code=400, detail="Missing 'rule' field")
        
        # Validate source format
        try:
            source_format_enum = SourceFormat(source_format)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid source format: {source_format}"
            )
        
        validation_result = await rule_converter.validate_rule(
            rule_content=rule_content,
            source_format=source_format_enum
        )
        
        return validation_result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Validation failed: {str(e)}"
        )


@app.get("/formats")
async def get_supported_formats():
    """Get supported source and target formats."""
    try:
        formats = await rule_converter.get_supported_formats()
        return formats
    except Exception as e:
        logger.error(f"Failed to get formats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get formats: {str(e)}"
        )


@app.get("/stats")
async def get_conversion_stats():
    """Get conversion statistics and system status."""
    try:
        stats = await rule_converter.get_conversion_stats()
        return stats
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get stats: {str(e)}"
        )


@app.get("/collections/{collection_name}/stats")
async def get_collection_stats(collection_name: str):
    """Get statistics for a specific collection."""
    try:
        from ..services.chromadb import chromadb_service
        
        stats = await chromadb_service.get_collection_stats(collection_name)
        return stats
    except Exception as e:
        logger.error(f"Failed to get collection stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get collection stats: {str(e)}"
        )


@app.post("/collections/{collection_name}/search")
async def search_collection(collection_name: str, request: Dict[str, Any]):
    """Search for similar documents in a collection."""
    try:
        from ..services.chromadb import chromadb_service
        
        query = request.get("query")
        n_results = request.get("n_results", 10)
        where = request.get("where")
        
        if not query:
            raise HTTPException(status_code=400, detail="Missing 'query' field")
        
        results = await chromadb_service.search_similar(
            collection_name=collection_name,
            query=query,
            n_results=n_results,
            where=where
        )
        
        return {
            "results": results,
            "total": len(results)
        }
    except Exception as e:
        logger.error(f"Collection search error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Collection search failed: {str(e)}"
        )


@app.post("/ingest/azure-sentinel")
async def ingest_azure_sentinel(request: Dict[str, Any]):
    """Ingest Azure Sentinel detection rules and hunting queries."""
    try:
        from ..data_ingestion.azure_sentinel_ingestion import azure_sentinel_ingestion
        
        force_refresh = request.get("force_refresh", False)
        
        stats = await azure_sentinel_ingestion.ingest_all(force_refresh=force_refresh)
        return stats
    except Exception as e:
        logger.error(f"Azure Sentinel ingestion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Azure Sentinel ingestion failed: {str(e)}"
        )


@app.post("/ingest/qradar/directory")
async def ingest_qradar_directory(request: Dict[str, Any]):
    """Ingest QRadar rules from a directory."""
    try:
        from ..data_ingestion.qradar_ingestion import qradar_ingestion
        
        directory_path = request.get("directory_path")
        force_refresh = request.get("force_refresh", False)
        
        if not directory_path:
            raise HTTPException(status_code=400, detail="Missing 'directory_path' field")
        
        stats = await qradar_ingestion.ingest_from_directory(
            directory_path=directory_path,
            force_refresh=force_refresh
        )
        return stats
    except Exception as e:
        logger.error(f"QRadar directory ingestion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"QRadar directory ingestion failed: {str(e)}"
        )


@app.post("/ingest/qradar/file")
async def ingest_qradar_file(request: Dict[str, Any]):
    """Ingest QRadar rules from a file."""
    try:
        from ..data_ingestion.qradar_ingestion import qradar_ingestion
        
        file_path = request.get("file_path")
        
        if not file_path:
            raise HTTPException(status_code=400, detail="Missing 'file_path' field")
        
        stats = await qradar_ingestion.ingest_from_file(file_path=file_path)
        return stats
    except Exception as e:
        logger.error(f"QRadar file ingestion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"QRadar file ingestion failed: {str(e)}"
        )


@app.post("/ingest/qradar/text")
async def ingest_qradar_text(request: Dict[str, Any]):
    """Ingest a QRadar rule from text content."""
    try:
        from ..data_ingestion.qradar_ingestion import qradar_ingestion
        
        rule_content = request.get("rule_content")
        rule_name = request.get("rule_name", "Manual Rule")
        
        if not rule_content:
            raise HTTPException(status_code=400, detail="Missing 'rule_content' field")
        
        stats = await qradar_ingestion.ingest_from_text(
            rule_content=rule_content,
            rule_name=rule_name
        )
        return stats
    except Exception as e:
        logger.error(f"QRadar text ingestion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"QRadar text ingestion failed: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "canonical.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        workers=settings.api_workers,
        log_level=settings.log_level.lower(),
        reload=settings.debug
    ) 