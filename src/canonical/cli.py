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
from .data_ingestion.all_ingestion import ingest_all_data
from .data_ingestion.azure_docs_ingestion import ingest_azure_docs


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
@click.argument('target_format', type=click.Choice(['kustoql', 'kibanaql', 'eql', 'qradar', 'spl']))
@click.option('--source-format', default='sigma', type=click.Choice(['sigma', 'qradar']), help='Source format')
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
@click.argument('rules_dir', type=click.Path(exists=True, path_type=Path))
@click.argument('target_format', type=click.Choice(['kustoql', 'kibanaql', 'eql', 'qradar', 'spl']))
@click.option('--source-format', default='sigma', type=click.Choice(['sigma', 'qradar']), help='Source format')
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
            else:
                extensions = ['*.yml', '*.yaml', '*.txt', '*.rule']
            
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
@click.option('--source-format', default='sigma', type=click.Choice(['sigma', 'qradar']), help='Source format')
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
    """Ingest all data sources (MITRE ATT&CK, CAR, Atomic Red Team)."""
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
            
        except Exception as e:
            click.echo(f"❌ Ingestion failed: {e}")
            sys.exit(1)
    
    asyncio.run(_ingest())


@data.command()
def ingest_azure_docs():
    """Ingest Azure Sentinel documentation PDF."""
    async def _ingest():
        try:
            click.echo("🚀 Starting Azure Sentinel documentation ingestion...")
            
            success = await ingest_azure_docs()
            
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