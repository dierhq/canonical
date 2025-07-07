#!/usr/bin/env python3
"""
Example script demonstrating QRadar to KustoQL conversion.

This script shows how to:
1. Parse a QRadar rule
2. Convert it to KustoQL using the Canonical converter
3. Display the results

Usage:
    python examples/qradar_to_kustoql_example.py
"""

import asyncio
import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from canonical.core.converter import RuleConverter
from canonical.core.models import SourceFormat, TargetFormat


async def main():
    """Main example function."""
    print("🔄 QRadar to KustoQL Conversion Example")
    print("=" * 50)
    
    # Example QRadar rule
    qradar_rule = """
Rule Name: Suspicious PowerShell Execution
Description: Detects suspicious PowerShell command execution with encoded commands
Rule Type: EVENT
Enabled: true
Severity: 7
Credibility: 8
Relevance: 9
Category: Suspicious Activity

when the event(s) are detected by the Local system
and when the event QID is one of the following "4688"
and when the process name contains "powershell.exe"
and when the command line contains "-EncodedCommand"
and when the event(s) occur in the last 5 minutes
    """
    
    print("📋 Original QRadar Rule:")
    print("-" * 30)
    print(qradar_rule)
    print()
    
    try:
        # Initialize the converter
        print("🚀 Initializing Canonical Rule Converter...")
        converter = RuleConverter()
        await converter.initialize()
        print("✅ Converter initialized successfully!")
        print()
        
        # Convert the rule
        print("🔄 Converting QRadar rule to KustoQL...")
        result = await converter.convert_qradar_to_kustoql(qradar_rule)
        
        print("📊 Conversion Results:")
        print("-" * 30)
        print(f"Success: {result.success}")
        print(f"Confidence Score: {result.confidence_score:.2f}")
        print()
        
        if result.success and result.target_rule:
            print("🎯 Generated KustoQL Rule:")
            print("-" * 30)
            print(result.target_rule)
            print()
            
            print("💡 Explanation:")
            print("-" * 30)
            print(result.explanation)
            print()
            
            if result.metadata:
                print("📋 Additional Metadata:")
                print("-" * 30)
                for key, value in result.metadata.items():
                    print(f"  {key}: {value}")
                print()
        else:
            print("❌ Conversion failed!")
            if result.error_message:
                print(f"Error: {result.error_message}")
        
        # Validate the original QRadar rule
        print("🔍 Validating original QRadar rule...")
        validation = await converter.validate_rule(qradar_rule, SourceFormat.QRADAR)
        
        print("📋 Validation Results:")
        print("-" * 30)
        print(f"Valid: {validation['valid']}")
        print(f"Complexity: {validation['complexity']}")
        print(f"Title: {validation['title']}")
        print(f"MITRE Techniques: {validation['mitre_techniques']}")
        
        if validation['errors']:
            print("Errors:")
            for error in validation['errors']:
                print(f"  - {error}")
        
    except Exception as e:
        print(f"❌ Error during conversion: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the example
    asyncio.run(main()) 