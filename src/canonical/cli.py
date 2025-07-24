"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Command-line interface for the Canonical SIEM rule converter.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional
import click
from loguru import logger

from .core.config import settings
from .core.models import SourceFormat, TargetFormat
from .core.converter import rule_converter
from .data_ingestion.sigma_ingestion import sigma_ingestion
from .data_ingestion.mitre_ingestion import mitre_ingestion
from .data_ingestion.car_ingestion import car_ingestion
from .data_ingestion.atomic_ingestion import atomic_ingestion
from .data_ingestion.azure_sentinel_ingestion import AzureSentinelIngestion
from .data_ingestion.qradar_docs_ingestion import qradar_docs_ingestion
from .data_ingestion.all_ingestion import ingest_all_data
from .data_ingestion.ecs_ingestion import ecs_ingestion
from .data_ingestion.custom_tables_ingestion import custom_tables_ingestion


@click.group()
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--log-file', help='Log file path')
def cli(debug: bool, log_file: Optional[str]):
    """Canonical SIEM Rule Converter CLI."""
    # Configure logging
    log_level = "DEBUG" if debug else settings.log_level
    logger.remove()
    
    if log_file:
        logger.add(log_file, level=log_level)
    else:
        logger.add(sys.stderr, level=log_level)
    
    logger.info(f"Starting Canonical CLI v{settings.app_version}")


@cli.command()
@click.argument('source_file', type=click.Path(exists=True, path_type=Path))
@click.argument('target_format', type=click.Choice(['kustoql', 'kibanaql', 'eql', 'qradar', 'spl', 'sigma']))
@click.option('--source-format', default='sigma', type=click.Choice(['sigma', 'qradar', 'kibanaql']), help='Source format')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file path')
@click.option('--org', '--organization', help='Organization name for custom table schemas')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def convert(source_file: Path, target_format: str, source_format: str, output: Optional[Path], org: Optional[str], verbose: bool):
    """Convert a rule from source format to target format."""
    async def _convert():
        try:
            # Read source rule
            with open(source_file, 'r', encoding='utf-8') as f:
                source_rule = f.read()
            
            # Prepare context with organization if provided
            context = {}
            if org:
                context['organization'] = org
                click.echo(f"Using custom tables for organization: {org}")
            # Note: If no org provided, the workflow will auto-detect available custom tables
            
            # Convert rule
            response = await rule_converter.convert_rule(
                source_rule=source_rule,
                source_format=SourceFormat(source_format),
                target_format=TargetFormat(target_format),
                context=context
            )
            
            if response.success:
                click.echo(f"✅ Conversion successful (confidence: {response.confidence_score:.2f})")
                
                if verbose:
                    click.echo(f"\nExplanation: {response.explanation}")
                    if response.mitre_techniques:
                        click.echo(f"MITRE Techniques: {', '.join(response.mitre_techniques)}")
                
                # Output converted rule
                if output:
                    with open(output, 'w', encoding='utf-8') as f:
                        f.write(response.target_rule)
                    click.echo(f"Converted rule saved to: {output}")
                else:
                    click.echo("\nConverted Rule:")
                    click.echo("-" * 40)
                    click.echo(response.target_rule)
            else:
                click.echo(f"❌ Conversion failed: {response.error_message}")
                sys.exit(1)
                
        except Exception as e:
            click.echo(f"❌ Error: {e}")
            sys.exit(1)
    
    asyncio.run(_convert())


@cli.command()
@click.argument('rules_dir', type=click.Path(exists=True, path_type=Path))
@click.argument('target_format', type=click.Choice(['kustoql', 'kibanaql', 'eql', 'qradar', 'spl', 'sigma']))
@click.option('--source-format', default='sigma', type=click.Choice(['sigma', 'qradar', 'kibanaql']), help='Source format')
@click.option('--output-dir', '-o', type=click.Path(path_type=Path), help='Output directory')
@click.option('--max-concurrent', default=5, help='Maximum concurrent conversions')
def batch_convert(rules_dir: Path, target_format: str, source_format: str, output_dir: Optional[Path], max_concurrent: int):
    """Convert multiple rules in batch."""
    async def _batch_convert():
        try:
            # Find all rule files based on source format
            rule_files = []
            if source_format == 'sigma':
                extensions = ['*.yml', '*.yaml']
            elif source_format == 'qradar':
                extensions = ['*.txt', '*.rule', '*.aql', '*.qradar']
            elif source_format == 'kibanaql':
                extensions = ['*.json', '*.yml', '*.yaml', '*.kql', '*.kibana']
            else:
                extensions = ['*.yml', '*.yaml', '*.txt', '*.rule', '*.json', '*.kql']
            
            for ext in extensions:
                rule_files.extend(rules_dir.rglob(ext))
            
            if not rule_files:
                click.echo("No rule files found")
                return
            
            click.echo(f"Found {len(rule_files)} rule files")
            
            # Prepare rules for batch conversion
            rules = []
            for rule_file in rule_files:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                rules.append({
                    "content": content,
                    "source_format": SourceFormat(source_format),
                    "file_path": rule_file
                })
            
            # Convert rules
            with click.progressbar(length=len(rules), label='Converting rules') as bar:
                responses = await rule_converter.batch_convert(
                    rules=rules,
                    target_format=TargetFormat(target_format),
                    max_concurrent=max_concurrent
                )
                bar.update(len(responses))
            
            # Process results
            successful = 0
            failed = 0
            
            for i, response in enumerate(responses):
                rule_file = rule_files[i]
                
                if response.success:
                    successful += 1
                    
                    if output_dir:
                        output_file = output_dir / f"{rule_file.stem}.{target_format}"
                        output_file.parent.mkdir(parents=True, exist_ok=True)
                        
                        with open(output_file, 'w', encoding='utf-8') as f:
                            f.write(response.target_rule)
                else:
                    failed += 1
                    click.echo(f"❌ Failed to convert {rule_file.name}: {response.error_message}")
            
            click.echo(f"\n✅ Batch conversion completed: {successful} successful, {failed} failed")
            
        except Exception as e:
            click.echo(f"❌ Error: {e}")
            sys.exit(1)
    
    asyncio.run(_batch_convert())


@cli.command()
@click.argument('rule_file', type=click.Path(exists=True, path_type=Path))
@click.option('--source-format', default='sigma', type=click.Choice(['sigma', 'qradar', 'kibanaql']), help='Source format')
def validate(rule_file: Path, source_format: str):
    """Validate a rule without converting it."""
    async def _validate():
        try:
            # Read rule
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule_content = f.read()
            
            # Validate rule
            result = await rule_converter.validate_rule(
                rule_content=rule_content,
                source_format=SourceFormat(source_format)
            )
            
            if result["valid"]:
                click.echo("✅ Rule is valid")
                click.echo(f"Title: {result['title']}")
                if result["description"]:
                    click.echo(f"Description: {result['description']}")
                if result["mitre_techniques"]:
                    click.echo(f"MITRE Techniques: {', '.join(result['mitre_techniques'])}")
                if result["complexity"]:
                    click.echo(f"Complexity: {result['complexity']['complexity_level']}")
            else:
                click.echo("❌ Rule is invalid")
                for error in result["errors"]:
                    click.echo(f"  - {error}")
                sys.exit(1)
                
        except Exception as e:
            click.echo(f"❌ Error: {e}")
            sys.exit(1)
    
    asyncio.run(_validate())


@cli.command()
def formats():
    """List supported formats."""
    async def _formats():
        try:
            formats = await rule_converter.get_supported_formats()
            
            click.echo("Supported formats:")
            click.echo(f"  Source: {', '.join(formats['source_formats'])}")
            click.echo(f"  Target: {', '.join(formats['target_formats'])}")
            
        except Exception as e:
            click.echo(f"❌ Error: {e}")
            sys.exit(1)
    
    asyncio.run(_formats())


@cli.command()
def stats():
    """Show conversion statistics and system status."""
    async def _stats():
        try:
            stats = await rule_converter.get_conversion_stats()
            
            click.echo("System Status:")
            click.echo(f"  Initialized: {stats['initialized']}")
            
            if "collections" in stats:
                click.echo("\nCollections:")
                for name, info in stats["collections"].items():
                    if "error" in info:
                        click.echo(f"  {name}: ❌ {info['error']}")
                    else:
                        click.echo(f"  {name}: {info.get('count', 0)} documents")
            
        except Exception as e:
            click.echo(f"❌ Error: {e}")
            sys.exit(1)
    
    asyncio.run(_stats())


@cli.group()
def data():
    """Data ingestion commands."""
    pass


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of repository')
def ingest_sigma(force_refresh: bool):
    """Ingest Sigma rules from SigmaHQ repository."""
    async def _ingest():
        try:
            click.echo("Starting Sigma rules ingestion...")
            
            stats = await sigma_ingestion.ingest_sigma_rules(force_refresh=force_refresh)
            
            click.echo(f"✅ Ingestion completed:")
            click.echo(f"  Total files: {stats['total_files']}")
            click.echo(f"  Successful: {stats['successful']}")
            click.echo(f"  Failed: {stats['failed']}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of data')
def ingest_mitre(force_refresh: bool):
    """Ingest MITRE ATT&CK framework data."""
    async def _ingest():
        try:
            click.echo("Starting MITRE ATT&CK ingestion...")
            
            stats = await mitre_ingestion.ingest_mitre_data(force_refresh=force_refresh)
            
            click.echo(f"✅ Ingestion completed:")
            click.echo(f"  Techniques: {stats['techniques']}")
            click.echo(f"  Tactics: {stats['tactics']}")
            click.echo(f"  Groups: {stats['groups']}")
            click.echo(f"  Software: {stats['software']}")
            click.echo(f"  Mitigations: {stats['mitigations']}")
            click.echo(f"  Total processed: {stats['total_processed']}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of repository')
def ingest_car(force_refresh: bool):
    """Ingest MITRE CAR analytics data."""
    async def _ingest():
        try:
            click.echo("Starting MITRE CAR ingestion...")
            
            stats = await car_ingestion.ingest_car_data(force_refresh=force_refresh)
            
            click.echo(f"✅ Ingestion completed:")
            click.echo(f"  Analytics: {stats['analytics']}")
            click.echo(f"  Successful: {stats['successful']}")
            click.echo(f"  Failed: {stats['failed']}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of repository')
def ingest_atomic(force_refresh: bool):
    """Ingest Atomic Red Team tests data."""
    async def _ingest():
        try:
            click.echo("Starting Atomic Red Team ingestion...")
            
            stats = await atomic_ingestion.ingest_atomic_data(force_refresh=force_refresh)
            
            click.echo(f"✅ Ingestion completed:")
            click.echo(f"  Techniques: {stats['techniques']}")
            click.echo(f"  Tests: {stats['tests']}")
            click.echo(f"  Successful: {stats['successful']}")
            click.echo(f"  Failed: {stats['failed']}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of all data')
def ingest_all(force_refresh: bool):
    """Ingest all data sources (MITRE ATT&CK, CAR, Atomic Red Team, Sigma Rules, Azure Sentinel, Azure Docs, QRadar Docs)."""
    async def _ingest():
        try:
            click.echo("Starting ingestion of all data sources...")
            
            stats = await ingest_all_data(force_refresh=force_refresh)
            
            click.echo(f"✅ All ingestion completed:")
            
            # Display MITRE ATT&CK stats
            if "mitre_attack" in stats:
                mitre_stats = stats["mitre_attack"]
                click.echo(f"\n  MITRE ATT&CK:")
                click.echo(f"    Techniques: {mitre_stats['techniques']}")
                click.echo(f"    Tactics: {mitre_stats['tactics']}")
                click.echo(f"    Groups: {mitre_stats['groups']}")
                click.echo(f"    Software: {mitre_stats['software']}")
                click.echo(f"    Mitigations: {mitre_stats['mitigations']}")
            
            # Display CAR stats
            if "mitre_car" in stats:
                car_stats = stats["mitre_car"]
                click.echo(f"\n  MITRE CAR:")
                click.echo(f"    Analytics: {car_stats['analytics']}")
                click.echo(f"    Successful: {car_stats['successful']}")
                click.echo(f"    Failed: {car_stats['failed']}")
            
            # Display Atomic Red Team stats
            if "atomic_red_team" in stats:
                atomic_stats = stats["atomic_red_team"]
                click.echo(f"\n  Atomic Red Team:")
                click.echo(f"    Techniques: {atomic_stats['techniques']}")
                click.echo(f"    Tests: {atomic_stats['tests']}")
                click.echo(f"    Successful: {atomic_stats['successful']}")
                click.echo(f"    Failed: {atomic_stats['failed']}")
            
            # Display Sigma Rules stats
            if "sigma_rules" in stats:
                sigma_stats = stats["sigma_rules"]
                click.echo(f"\n  Sigma Rules:")
                click.echo(f"    Total files: {sigma_stats['total_files']}")
                click.echo(f"    Successful: {sigma_stats['successful']}")
                click.echo(f"    Failed: {sigma_stats['failed']}")
            
            # Display Azure Sentinel stats
            if "azure_sentinel" in stats:
                azure_stats = stats["azure_sentinel"]
                click.echo(f"\n  Azure Sentinel:")
                if "detections" in azure_stats:
                    det_stats = azure_stats["detections"]
                    click.echo(f"    Detections - Total: {det_stats['total_files']}, Successful: {det_stats['successful']}, Failed: {det_stats['failed']}")
                if "hunting" in azure_stats:
                    hunt_stats = azure_stats["hunting"]
                    click.echo(f"    Hunting - Total: {hunt_stats['total_files']}, Successful: {hunt_stats['successful']}, Failed: {hunt_stats['failed']}")
            
            # Display Azure Docs stats
            if "azure_docs" in stats:
                azure_docs_stats = stats["azure_docs"]
                click.echo(f"\n  Azure Sentinel Documentation:")
                click.echo(f"    Status: {'✅ Success' if azure_docs_stats['success'] else '❌ Failed'}")
            
            # Display QRadar Docs stats
            if "qradar_docs" in stats:
                qradar_stats = stats["qradar_docs"]
                click.echo(f"\n  QRadar Documentation:")
                click.echo(f"    Total documents: {qradar_stats['total_documents']}")
                click.echo(f"    Successful: {qradar_stats['successful']}")
                click.echo(f"    Failed: {qradar_stats['failed']}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of repository')
def ingest_azure_sentinel(force_refresh: bool):
    """Ingest Azure Sentinel detection rules and hunting queries."""
    async def _ingest():
        try:
            click.echo("Starting Azure Sentinel ingestion...")
            
            azure_ingestion = AzureSentinelIngestion()
            stats = await azure_ingestion.ingest_all(force_refresh=force_refresh)
            
            click.echo(f"✅ Ingestion completed:")
            click.echo(f"  Detection rules: {stats.get('detections', {}).get('successful', 0)}")
            click.echo(f"  Hunting queries: {stats.get('hunting', {}).get('successful', 0)}")
            click.echo(f"  Total successful: {stats.get('detections', {}).get('successful', 0) + stats.get('hunting', {}).get('successful', 0)}")
            click.echo(f"  Total failed: {stats.get('detections', {}).get('failed', 0) + stats.get('hunting', {}).get('failed', 0)}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            logger.error(f"Ingestion error: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of repository')
def ingest_azure_detections(force_refresh: bool):
    """Ingest Azure Sentinel detection rules only."""
    async def _ingest():
        try:
            click.echo("Starting Azure Sentinel detection rules ingestion...")
            
            azure_ingestion = AzureSentinelIngestion()
            if force_refresh:
                await azure_ingestion._update_repository(force_refresh=True)
            
            stats = await azure_ingestion.ingest_detections()
            
            click.echo(f"✅ Detection rules ingestion completed:")
            click.echo(f"  Total files: {stats.get('total_files', 0)}")
            click.echo(f"  Successful: {stats.get('successful', 0)}")
            click.echo(f"  Failed: {stats.get('failed', 0)}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            logger.error(f"Ingestion error: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of repository')
def ingest_azure_hunting(force_refresh: bool):
    """Ingest Azure Sentinel hunting queries only."""
    async def _ingest():
        try:
            click.echo("Starting Azure Sentinel hunting queries ingestion...")
            
            azure_ingestion = AzureSentinelIngestion()
            if force_refresh:
                await azure_ingestion._update_repository(force_refresh=True)
            
            stats = await azure_ingestion.ingest_hunting_queries()
            
            click.echo(f"✅ Hunting queries ingestion completed:")
            click.echo(f"  Total files: {stats.get('total_files', 0)}")
            click.echo(f"  Successful: {stats.get('successful', 0)}")
            click.echo(f"  Failed: {stats.get('failed', 0)}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            logger.error(f"Ingestion error: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
def ingest_azure_docs():
    """Ingest Azure Sentinel documentation PDF."""
    async def _ingest():
        try:
            click.echo("🚀 Starting Azure Sentinel documentation ingestion...")
            
            # Import here to avoid naming conflict
            from .data_ingestion.azure_docs_ingestion import ingest_azure_docs as run_azure_ingestion
            success = await run_azure_ingestion()
            
            if success:
                click.echo("✅ Azure Sentinel documentation ingestion completed successfully!")
            else:
                click.echo("❌ Azure Sentinel documentation ingestion failed!")
                sys.exit(1)
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            logger.error(f"Ingestion error: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of collection')
def ingest_qradar_docs(force_refresh: bool):
    """Ingest QRadar documentation from IBM blog post."""
    async def _ingest():
        try:
            click.echo("🚀 Starting QRadar documentation ingestion...")
            
            stats = await qradar_docs_ingestion.ingest_qradar_blog_docs(force_refresh=force_refresh)
            
            click.echo(f"✅ QRadar documentation ingestion completed:")
            click.echo(f"  Total documents: {stats['total_documents']}")
            click.echo(f"  Successful: {stats['successful']}")
            click.echo(f"  Failed: {stats['failed']}")
            click.echo(f"  Collection: {stats['collection']}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            logger.error(f"Ingestion error: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of collection')
def ingest_ecs(force_refresh: bool):
    """Ingest Elastic Common Schema (ECS) field reference documentation."""
    async def _ingest():
        try:
            click.echo("🚀 Starting ECS field reference ingestion...")
            
            stats = await ecs_ingestion.ingest_ecs_fields(force_refresh=force_refresh)
            
            if stats.get('skipped'):
                click.echo(f"⏭️  ECS collection already exists with {stats['total_documents']} documents")
                click.echo("   Use --force-refresh to reload the data")
            else:
                click.echo(f"✅ ECS field reference ingestion completed:")
                click.echo(f"  Field sets processed: {stats['field_sets_processed']}")
                click.echo(f"  Total documents: {stats['total_documents']}")
                click.echo(f"  Successful: {stats['successful']}")
                click.echo(f"  Failed: {stats['failed']}")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            logger.error(f"ECS ingestion error: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())

@data.command()
@click.argument('json_path', type=click.Path(exists=True))
@click.option('--force-refresh', is_flag=True, help='Force refresh of collection')
def ingest_custom_tables(json_path: str, force_refresh: bool):
    """Ingest custom table schemas from JSON file for deployment-ready rule conversion."""
    async def _ingest():
        try:
            click.echo(f"🚀 Starting custom tables ingestion from: {json_path}")
            
            stats = await custom_tables_ingestion.ingest_custom_tables(json_path, force_refresh=force_refresh)
            
            if stats.get('skipped'):
                click.echo(f"⏭️  Custom tables already exist ({stats['total_documents']} documents)")
                click.echo("   Use --force-refresh to reload the data")
            else:
                click.echo(f"✅ Custom tables ingestion completed:")
                click.echo(f"  Tables processed: {stats['tables_processed']}")
                click.echo(f"  Total documents: {stats['total_documents']}")
                click.echo(f"  Successful: {stats['successful']}")
                click.echo(f"  Failed: {stats['failed']}")
                click.echo(f"  🎯 Tables are now available for deployment-ready rule conversion!")
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            logger.error(f"Custom tables ingestion error: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())



@cli.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
@click.option('--reload', is_flag=True, help='Enable auto-reload')
def serve(host: str, port: int, reload: bool):
    """Start the API server."""
    import uvicorn
    
    uvicorn.run(
        "canonical.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level=settings.log_level.lower()
    )


@cli.group()
def schema():
    """Manage custom table schemas for organization-specific data."""
    pass


@schema.command("add-custom-tables")
@click.argument('schema_file', type=click.Path(exists=True, path_type=Path))
@click.option('--org', '--organization', required=True, help='Organization name')
@click.option('--validate-only', is_flag=True, help='Only validate schema without adding')
def add_custom_tables(schema_file: Path, org: str, validate_only: bool):
    """Add custom table schemas from JSON file.
    
    Example:
        canonical schema add-custom-tables custom_tables.json --org acme
    """
    async def _add_custom_tables():
        try:
            from .services.custom_tables import custom_table_service
            
            if validate_only:
                # Only validate the schema
                import json
                with open(schema_file, 'r', encoding='utf-8') as f:
                    schema_data = json.load(f)
                
                is_valid, errors = custom_table_service.validate_schema(schema_data)
                if is_valid:
                    click.echo(click.style("✓ Schema validation passed", fg='green'))
                    schema = custom_table_service.parse_schema(schema_data, org)
                    click.echo(f"Found {len(schema.tables)} tables:")
                    for table in schema.tables:
                        click.echo(f"  - {table.name} ({len(table.columns)} columns)")
                else:
                    click.echo(click.style("✗ Schema validation failed:", fg='red'))
                    for error in errors:
                        click.echo(f"  {error}")
                    sys.exit(1)
            else:
                # Add the custom tables
                success, message = await custom_table_service.add_custom_tables(schema_file, org)
                if success:
                    click.echo(click.style(f"✓ {message}", fg='green'))
                else:
                    click.echo(click.style(f"✗ {message}", fg='red'))
                    sys.exit(1)
                    
        except Exception as e:
            click.echo(click.style(f"Error: {str(e)}", fg='red'))
            sys.exit(1)
    
    asyncio.run(_add_custom_tables())


@schema.command("list-custom-tables")
@click.option('--org', '--organization', help='Organization name (show all if not specified)')
def list_custom_tables(org: Optional[str]):
    """List custom table schemas.
    
    Example:
        canonical schema list-custom-tables --org acme
        canonical schema list-custom-tables  # List all organizations
    """
    async def _list_custom_tables():
        try:
            from .services.custom_tables import custom_table_service
            
            tables = await custom_table_service.list_custom_tables(org)
            
            if not tables:
                if org:
                    click.echo(f"No custom tables found for organization '{org}'")
                else:
                    click.echo("No custom tables found")
                return
            
            click.echo("Custom Table Schemas:")
            click.echo("-" * 50)
            
            for table_info in tables:
                click.echo(f"Organization: {table_info['organization']}")
                click.echo(f"Collection: {table_info['collection']}")
                click.echo(f"Table Count: {table_info['table_count']}")
                click.echo(f"Created: {table_info['created_date']}")
                click.echo("-" * 50)
                
        except Exception as e:
            click.echo(click.style(f"Error: {str(e)}", fg='red'))
            sys.exit(1)
    
    asyncio.run(_list_custom_tables())


@schema.command("remove-custom-tables")
@click.option('--org', '--organization', required=True, help='Organization name')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def remove_custom_tables(org: str, confirm: bool):
    """Remove custom table schemas for an organization.
    
    Example:
        canonical schema remove-custom-tables --org acme --confirm
    """
    async def _remove_custom_tables():
        try:
            from .services.custom_tables import custom_table_service
            
            if not confirm:
                click.echo(f"This will remove ALL custom tables for organization '{org}'")
                if not click.confirm("Are you sure you want to continue?"):
                    click.echo("Operation cancelled")
                    return
            
            success, message = await custom_table_service.remove_custom_tables(org)
            if success:
                click.echo(click.style(f"✓ {message}", fg='green'))
            else:
                click.echo(click.style(f"✗ {message}", fg='red'))
                sys.exit(1)
                
        except Exception as e:
            click.echo(click.style(f"Error: {str(e)}", fg='red'))
            sys.exit(1)
    
    asyncio.run(_remove_custom_tables())


@schema.command("validate")
@click.argument('schema_file', type=click.Path(exists=True, path_type=Path))
def validate_schema(schema_file: Path):
    """Validate a custom table schema file.
    
    Example:
        canonical schema validate custom_tables.json
    """
    async def _validate_schema():
        try:
            from .services.custom_tables import custom_table_service
            import json
            
            with open(schema_file, 'r', encoding='utf-8') as f:
                schema_data = json.load(f)
            
            is_valid, errors = custom_table_service.validate_schema(schema_data)
            
            if is_valid:
                click.echo(click.style("✓ Schema validation passed", fg='green'))
                
                # Show schema summary
                schema = custom_table_service.parse_schema(schema_data)
                click.echo(f"\nSchema Summary:")
                click.echo(f"  Organization: {schema.organization or 'Not specified'}")
                click.echo(f"  Version: {schema.version}")
                click.echo(f"  Tables: {len(schema.tables)}")
                
                for table in schema.tables:
                    click.echo(f"    - {table.name} ({len(table.columns)} columns)")
                    if table.description:
                        click.echo(f"      Description: {table.description}")
                    if table.retentionInDays:
                        click.echo(f"      Retention: {table.retentionInDays} days")
            else:
                click.echo(click.style("✗ Schema validation failed:", fg='red'))
                for error in errors:
                    click.echo(f"  {error}")
                sys.exit(1)
                
        except json.JSONDecodeError as e:
            click.echo(click.style(f"Invalid JSON: {str(e)}", fg='red'))
            sys.exit(1)
        except Exception as e:
            click.echo(click.style(f"Error: {str(e)}", fg='red'))
            sys.exit(1)
    
    asyncio.run(_validate_schema())


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main() 