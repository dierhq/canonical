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
import json
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
from .data_ingestion.ecs_ingestion import ecs_ingestion
from .data_ingestion.all_ingestion import ingest_all_data
from .data_ingestion.schema_ingestion import schema_ingestion
from .services.schema_service import SchemaService
from .core.models import SchemaIngestionRequest


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
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def convert(source_file: Path, target_format: str, source_format: str, output: Optional[Path], verbose: bool):
    """Convert a rule from source format to target format."""
    async def _convert():
        try:
            # Read source rule
            with open(source_file, 'r', encoding='utf-8') as f:
                source_rule = f.read()
            
            # Convert rule
            response = await rule_converter.convert_rule(
                source_rule=source_rule,
                source_format=SourceFormat(source_format),
                target_format=TargetFormat(target_format)
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
@click.argument('source_file', type=click.Path(exists=True, path_type=Path))
@click.argument('target_format', type=click.Choice(['kustoql', 'kibanaql', 'eql', 'qradar', 'spl', 'sigma']))
@click.option('--source-format', default='sigma', type=click.Choice(['sigma', 'qradar', 'kibanaql']), help='Source format')
@click.option('--schema', '-s', help='Schema name for environment-aware conversion')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--show-validation', is_flag=True, help='Show schema validation results')
def convert_with_schema(source_file: Path, target_format: str, source_format: str, schema: Optional[str], output: Optional[Path], verbose: bool, show_validation: bool):
    """Convert a rule with schema-aware field mappings."""
    async def _convert():
        try:
            # Read source rule
            with open(source_file, 'r', encoding='utf-8') as f:
                source_rule = f.read()
            
            # Prepare context with schema information
            context = {}
            if schema:
                context["schema_name"] = schema
                click.echo(f"Using schema: {schema}")
            
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
                
                # Show schema validation results if requested
                if show_validation and response.metadata and "schema_validation" in response.metadata:
                    validation = response.metadata["schema_validation"]
                    click.echo(f"\n📊 Schema Validation Results:")
                    click.echo(f"  Field Coverage: {validation['field_coverage']:.1%}")
                    click.echo(f"  Valid: {'✅' if validation['is_valid'] else '❌'}")
                    click.echo(f"  Confidence: {validation['confidence_score']:.2f}")
                    
                    if validation['validated_fields']:
                        click.echo(f"  Validated Fields: {', '.join(validation['validated_fields'])}")
                    
                    if validation['missing_fields']:
                        click.echo(f"  Missing Fields: {', '.join(validation['missing_fields'])}")
                    
                    if validation['issues']:
                        click.echo(f"  Issues:")
                        for issue in validation['issues']:
                            click.echo(f"    - {issue}")
                    
                    if validation['suggestions']:
                        click.echo(f"  Suggestions:")
                        for suggestion in validation['suggestions']:
                            click.echo(f"    - {suggestion}")
                
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
@click.option('--no-gpu', is_flag=True, help='Disable GPU acceleration (use CPU only)')
def ingest_all(force_refresh: bool, no_gpu: bool):
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
@click.argument('schema_path', type=click.Path(exists=True, path_type=Path))
@click.option('--name', help='Custom schema name')
@click.option('--overwrite', is_flag=True, help='Overwrite existing schema')
def add_schema(schema_path: Path, name: Optional[str], overwrite: bool):
    """Add an environment schema from JSON file."""
    async def _add_schema():
        try:
            click.echo(f"📋 Adding schema from: {schema_path}")
            
            # Initialize services
            from .services.schema_service import schema_service
            
            # Parse schema file
            with open(schema_path, 'r') as f:
                schema_data = json.load(f)
            
            # Add schema name if not present
            if 'name' not in schema_data:
                schema_data['name'] = name
            
            # Ingest schema
            await schema_service.ingest_schema(schema_data)
            
            click.echo(f"✅ Schema '{name}' added successfully!")
            click.echo(f"  Tables: {len(schema_data.get('tables', []))}")
            total_columns = sum(len(table.get('columns', [])) for table in schema_data.get('tables', []))
            click.echo(f"  Columns: {total_columns}")
            
        except Exception as e:
            click.echo(f"❌ Error: {e}")
            logger.error(f"Schema ingestion error: {e}")
            sys.exit(1)
    
    asyncio.run(_add_schema())


@data.command()
def list_schemas():
    """List all available environment schemas."""
    async def _list_schemas():
        try:
            click.echo("📋 Available schemas:")
            
            # Initialize services
            from .services.schema_service import schema_service
            
            # Get schemas
            schema_names = schema_service.list_schemas()
            
            if schema_names:
                for schema_name in schema_names:
                    schema_data = schema_service.get_schema(schema_name)
                    if schema_data:
                        click.echo(f"  📊 {schema_data.get('name', schema_name)}")
                        click.echo(f"    Version: {schema_data.get('version', 'N/A')}")
                        click.echo(f"    Tables: {len(schema_data.get('tables', []))}")
                    click.echo()
            else:
                click.echo("  No schemas found. Use 'data add-schema' to add one.")
            
        except Exception as e:
            click.echo(f"❌ Error: {e}")
            logger.error(f"Schema listing error: {e}")
            sys.exit(1)
    
    asyncio.run(_list_schemas())


@data.command()
@click.argument('schema_name')
def remove_schema(schema_name: str):
    """Remove an environment schema."""
    async def _remove_schema():
        try:
            click.echo(f"🗑️  Removing schema: {schema_name}")
            
            # Initialize services
            from .services.schema_service import schema_service
            
            # Check if schema exists
            if schema_name not in schema_service.list_schemas():
                click.echo(f"❌ Schema '{schema_name}' not found")
                sys.exit(1)
            
            # Remove schema
            success = schema_service.remove_schema(schema_name)
            if success:
                click.echo(f"✅ Schema '{schema_name}' removed successfully!")
            else:
                click.echo(f"❌ Failed to remove schema '{schema_name}'")
                sys.exit(1)
            
        except Exception as e:
            click.echo(f"❌ Error: {e}")
            logger.error(f"Schema removal error: {e}")
            sys.exit(1)
    
    asyncio.run(_remove_schema())


@data.command()
@click.argument('field_name')
@click.option('--schema', help='Limit search to specific schema')
@click.option('--limit', default=5, help='Maximum number of results')
def find_field(field_name: str, schema: Optional[str], limit: int):
    """Find field mappings in environment schemas."""
    async def _find_field():
        try:
            click.echo(f"🔍 Finding mappings for field: {field_name}")
            
            # Initialize services
            from .services.schema_service import schema_service
            
            # Search for field mappings
            results = schema_service.find_field_mappings(field_name)
            
            if results:
                total_matches = sum(len(matches) for matches in results.values())
                click.echo(f"\n📊 Found {total_matches} potential mappings:")
                for schema_name, matches in results.items():
                    click.echo(f"\n  Schema: {schema_name}")
                    for match in matches[:limit]:
                        click.echo(f"    🎯 {match['table']}.{match['column']}")
                        click.echo(f"      Type: {match['type']}")
                        if match.get('description'):
                            click.echo(f"      Description: {match['description']}")
                        click.echo()
            else:
                click.echo("  No field mappings found.")
            
        except Exception as e:
            click.echo(f"❌ Error: {e}")
            logger.error(f"Field mapping error: {e}")
            sys.exit(1)
    
    asyncio.run(_find_field())


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


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main() 

@data.command()
@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh of ECS field data')
def ingest_ecs(force_refresh: bool):
    """Ingest ECS (Elastic Common Schema) field reference data for EQL/KibanaQL field knowledge."""
    async def _ingest():
        try:
            click.echo("🔍 Starting ECS field reference ingestion...")
            click.echo("📖 This will scrape Elastic Common Schema documentation")
            click.echo("   to improve EQL/KibanaQL field knowledge for rule conversion")
            
            stats = await ecs_ingestion.ingest_ecs_fields(force_refresh=force_refresh)
            
            if stats.get("success", False):
                click.echo(f"\n✅ ECS field reference ingestion completed:")
                click.echo(f"   Field Sets: {stats.get('field_sets', 0)}")
                click.echo(f"   Total Fields: {stats.get('total_fields', 0)}")
                click.echo(f"   Successfully Ingested: {stats.get('successful', 0)}")
                click.echo(f"   Failed: {stats.get('failed', 0)}")
                
                if stats.get('cached', False):
                    click.echo(f"   📋 Data was already cached")
                
                click.echo(f"\n💡 ECS fields are now available for EQL/KibanaQL field mapping!")
                click.echo(f"   Collection: ecs_fields")
                
            else:
                click.echo(f"❌ ECS field reference ingestion failed: {stats.get('error', 'Unknown error')}")
                sys.exit(1)
                
        except Exception as e:
            click.echo(f"❌ ECS ingestion failed: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.option('--force-refresh', is_flag=True, help='Force refresh and overwrite existing schemas')
def ingest_schemas(force_refresh: bool):
    """Ingest all environment schemas from the schemas directory."""
    async def _ingest():
        try:
            click.echo("📋 Starting schema ingestion from schemas directory...")
            
            stats = await schema_ingestion.ingest_all_schemas(force_refresh=force_refresh)
            
            if stats.get("success", False):
                click.echo(f"✅ Schema ingestion completed:")
                click.echo(f"  Total files: {stats['total_files']}")
                click.echo(f"  Successful: {stats['successful']}")
                click.echo(f"  Failed: {stats['failed']}")
                
                if stats.get('results'):
                    click.echo("\n📊 Results:")
                    for result in stats['results']:
                        file_name = result['file']
                        file_result = result['result']
                        if file_result.get('success', False):
                            schema_name = file_result.get('schema_name', 'Unknown')
                            tables = file_result.get('tables', 0)
                            columns = file_result.get('total_columns', 0)
                            click.echo(f"  ✅ {file_name} → {schema_name} ({tables} tables, {columns} columns)")
                        else:
                            error = file_result.get('error', 'Unknown error')
                            click.echo(f"  ❌ {file_name} → {error}")
            else:
                error = stats.get('error', 'Unknown error')
                click.echo(f"❌ Schema ingestion failed: {error}")
                sys.exit(1)
                
        except Exception as e:
            click.echo(f"❌ Schema ingestion failed: {e}")
            logger.error(f"Schema ingestion error: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
@click.argument('query')
@click.option('--limit', default=5, help='Maximum number of results')
def search_schema_fields(query: str, limit: int):
    """Search schema fields semantically for field mapping."""
    async def _search():
        try:
            click.echo(f"🔍 Searching schema fields for: '{query}'")
            
            results = await schema_ingestion.search_schema_fields(query, limit)
            
            if results:
                click.echo(f"\n📊 Found {len(results)} matches:")
                for result in results:
                    metadata = result.get('metadata', {})
                    schema_name = metadata.get('schema_name', 'Unknown')
                    table_name = metadata.get('table_name', 'Unknown')
                    column_name = metadata.get('column_name', 'Unknown')
                    column_type = metadata.get('column_type', 'Unknown')
                    
                    click.echo(f"  🎯 {schema_name}.{table_name}.{column_name}")
                    click.echo(f"    Type: {column_type}")
                    if metadata.get('description'):
                        click.echo(f"    Description: {metadata['description']}")
                    click.echo()
            else:
                click.echo("  No schema fields found.")
            
        except Exception as e:
            click.echo(f"❌ Search failed: {e}")
            logger.error(f"Schema search error: {e}")
            sys.exit(1)
    
    asyncio.run(_search())


@data.command()
def schema_stats():
    """Show schema collection statistics."""
    async def _stats():
        try:
            click.echo("📊 Schema Collection Statistics:")
            
            stats = await schema_ingestion.get_collection_stats()
            
            click.echo(f"  Collection: {stats.get('collection', 'Unknown')}")
            click.echo(f"  Total Fields in ChromaDB: {stats.get('total_fields', 0)}")
            click.echo(f"  Schemas Loaded: {stats.get('schemas_loaded', 0)}")
            
            if 'error' in stats:
                click.echo(f"  Error: {stats['error']}")
            
        except Exception as e:
            click.echo(f"❌ Stats failed: {e}")
            logger.error(f"Schema stats error: {e}")
            sys.exit(1)
    
    asyncio.run(_stats())
