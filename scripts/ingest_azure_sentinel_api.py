#!/usr/bin/env python3
"""
Azure Sentinel Data Ingestion via GitHub API

This script downloads Azure Sentinel detection rules and hunting queries
using GitHub's API instead of git clone to avoid repository size issues.
"""

import asyncio
import requests
import yaml
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import time

# Add the canonical package to the path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from canonical.services.chromadb import ChromaDBService
from canonical.services.embedding import EmbeddingService

@dataclass
class AzureSentinelRule:
    """Azure Sentinel detection rule or hunting query"""
    id: str
    name: str
    description: str
    severity: str
    tactics: List[str]
    techniques: List[str]
    query: str
    rule_type: str  # 'detection' or 'hunting'
    category: str
    metadata: Dict[str, Any]

class AzureSentinelAPIIngester:
    """Ingest Azure Sentinel rules via GitHub API"""
    
    def __init__(self):
        self.base_url = "https://api.github.com/repos/Azure/Azure-Sentinel/contents"
        self.raw_base_url = "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master"
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Canonical-Rule-Converter/1.0'
        })
        
    async def ingest_all(self) -> bool:
        """Ingest all Azure Sentinel detection rules and hunting queries"""
        try:
            print("🚀 Starting Azure Sentinel ingestion via GitHub API...")
            
            # Initialize services
            embedding_service = EmbeddingService()
            await embedding_service.initialize()
            
            chromadb_service = ChromaDBService()
            await chromadb_service.initialize()
            
            detection_rules = []
            hunting_queries = []
            
            # Download detection rules
            print("📥 Downloading detection rules...")
            detection_rules = await self._download_detections()
            
            # Download hunting queries  
            print("📥 Downloading hunting queries...")
            hunting_queries = await self._download_hunting_queries()
            
            # Process and store in ChromaDB
            if detection_rules:
                print(f"💾 Storing {len(detection_rules)} detection rules...")
                await self._store_rules(detection_rules, "azure_sentinel_detections", chromadb_service, embedding_service)
            
            if hunting_queries:
                print(f"💾 Storing {len(hunting_queries)} hunting queries...")
                await self._store_rules(hunting_queries, "azure_sentinel_hunting", chromadb_service, embedding_service)
            
            total_rules = len(detection_rules) + len(hunting_queries)
            print(f"✅ Successfully ingested {total_rules} Azure Sentinel rules!")
            return True
            
        except Exception as e:
            print(f"❌ Ingestion failed: {e}")
            return False
    
    async def _download_detections(self) -> List[AzureSentinelRule]:
        """Download detection rules from Detections directory"""
        return await self._download_from_directory("Detections", "detection")
    
    async def _download_hunting_queries(self) -> List[AzureSentinelRule]:
        """Download hunting queries from Hunting Queries directory"""
        return await self._download_from_directory("Hunting Queries", "hunting")
    
    async def _download_from_directory(self, directory: str, rule_type: str) -> List[AzureSentinelRule]:
        """Download rules from a specific directory"""
        rules = []
        
        try:
            print(f"🔍 Exploring {directory} directory...")
            
            # Get directory contents
            url = f"{self.base_url}/{directory.replace(' ', '%20')}"
            response = self.session.get(url, timeout=30)
            
            if response.status_code != 200:
                print(f"❌ Failed to access {directory}: {response.status_code}")
                return rules
            
            contents = response.json()
            
            # Process subdirectories (categories)
            categories = [item for item in contents if item['type'] == 'dir']
            print(f"📂 Found {len(categories)} categories in {directory}")
            
            for category in categories[:10]:  # Limit to first 10 categories to avoid overwhelming
                category_name = category['name']
                print(f"  📁 Processing category: {category_name}")
                
                category_rules = await self._download_category_rules(
                    directory, category_name, rule_type
                )
                rules.extend(category_rules)
                
                # Rate limiting
                await asyncio.sleep(0.5)
            
            print(f"✅ Downloaded {len(rules)} rules from {directory}")
            return rules
            
        except Exception as e:
            print(f"❌ Error downloading from {directory}: {e}")
            return rules
    
    async def _download_category_rules(self, directory: str, category: str, rule_type: str) -> List[AzureSentinelRule]:
        """Download rules from a specific category"""
        rules = []
        
        try:
            # Get category contents
            url = f"{self.base_url}/{directory.replace(' ', '%20')}/{category}"
            response = self.session.get(url, timeout=30)
            
            if response.status_code != 200:
                return rules
            
            contents = response.json()
            
            # Find YAML files
            yaml_files = [item for item in contents if item['name'].endswith(('.yaml', '.yml'))]
            
            for file_info in yaml_files[:5]:  # Limit files per category
                file_name = file_info['name']
                
                try:
                    # Download file content
                    file_url = f"{self.raw_base_url}/{directory.replace(' ', '%20')}/{category}/{file_name}"
                    file_response = self.session.get(file_url, timeout=15)
                    
                    if file_response.status_code == 200:
                        rule = await self._parse_rule_file(
                            file_response.text, file_name, category, rule_type
                        )
                        if rule:
                            rules.append(rule)
                
                except Exception as e:
                    print(f"    ⚠️ Error downloading {file_name}: {e}")
                    continue
                
                # Rate limiting
                await asyncio.sleep(0.2)
        
        except Exception as e:
            print(f"    ❌ Error in category {category}: {e}")
        
        return rules
    
    async def _parse_rule_file(self, content: str, filename: str, category: str, rule_type: str) -> Optional[AzureSentinelRule]:
        """Parse a YAML rule file into AzureSentinelRule"""
        try:
            # Parse YAML
            data = yaml.safe_load(content)
            if not data:
                return None
            
            # Extract required fields with defaults
            rule_id = data.get('id', filename.replace('.yaml', '').replace('.yml', ''))
            name = data.get('name', filename)
            description = data.get('description', '')
            severity = data.get('severity', 'Medium')
            
            # Extract MITRE tactics and techniques
            tactics = []
            techniques = []
            
            if 'tactics' in data:
                tactics = data['tactics'] if isinstance(data['tactics'], list) else [data['tactics']]
            
            if 'relevantTechniques' in data:
                techniques = data['relevantTechniques']
            elif 'techniques' in data:
                techniques = data['techniques']
            
            # Extract query
            query = data.get('query', '')
            if not query and 'properties' in data:
                query = data['properties'].get('query', '')
            
            # Create rule object
            rule = AzureSentinelRule(
                id=rule_id,
                name=name,
                description=description,
                severity=severity,
                tactics=tactics,
                techniques=techniques,
                query=query,
                rule_type=rule_type,
                category=category,
                metadata={
                    'filename': filename,
                    'source': 'Azure Sentinel',
                    'raw_data': data
                }
            )
            
            return rule
            
        except Exception as e:
            print(f"    ⚠️ Error parsing {filename}: {e}")
            return None
    
    async def _store_rules(self, rules: List[AzureSentinelRule], collection_name: str, 
                          chromadb_service: ChromaDBService, embedding_service: EmbeddingService):
        """Store rules in ChromaDB"""
        
        documents = []
        metadatas = []
        ids = []
        
        for i, rule in enumerate(rules):
            # Create document text for embedding
            doc_text = f"""
            Title: {rule.name}
            Description: {rule.description}
            Severity: {rule.severity}
            Category: {rule.category}
            Type: {rule.rule_type}
            Tactics: {', '.join(rule.tactics)}
            Techniques: {', '.join(rule.techniques)}
            Query: {rule.query[:500]}...
            """
            
            documents.append(doc_text.strip())
            
            metadatas.append({
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'category': rule.category,
                'rule_type': rule.rule_type,
                'tactics': json.dumps(rule.tactics),
                'techniques': json.dumps(rule.techniques),
                'query': rule.query,
                'source': 'Azure Sentinel',
                'filename': rule.metadata.get('filename', '')
            })
            
            ids.append(f"azure_sentinel_{rule.rule_type}_{i}")
        
        # Store documents (ChromaDB will generate embeddings internally)
        if documents:
            print(f"💾 Storing {len(documents)} documents in ChromaDB collection: {collection_name}")
            await chromadb_service.add_documents(
                collection_name=collection_name,
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )

async def main():
    """Main ingestion function"""
    print("🎯 Azure Sentinel API Ingestion Starting...")
    
    ingester = AzureSentinelAPIIngester()
    success = await ingester.ingest_all()
    
    if success:
        print("🎉 Azure Sentinel ingestion completed successfully!")
        return 0
    else:
        print("❌ Azure Sentinel ingestion failed!")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 