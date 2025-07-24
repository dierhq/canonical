"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Custom table management service for organization-specific schemas.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from loguru import logger

from ..core.models import CustomTable, CustomTableColumn, CustomTableSchema
from ..core.config import settings
from .chromadb import chromadb_service


class CustomTableService:
    """Service for managing custom table schemas."""
    
    def __init__(self):
        """Initialize the custom table service."""
        self.collection_prefix = "custom_tables"
    
    def validate_schema(self, schema_data: Dict) -> Tuple[bool, List[str]]:
        """Validate custom table schema.
        
        Args:
            schema_data: Dictionary containing schema definition
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        try:
            # Check required fields
            if "tables" not in schema_data:
                errors.append("Schema must contain 'tables' field")
                return False, errors
            
            if not isinstance(schema_data["tables"], list):
                errors.append("'tables' must be a list")
                return False, errors
            
            if len(schema_data["tables"]) == 0:
                errors.append("Schema must contain at least one table")
                return False, errors
            
            # Validate each table
            table_names = set()
            for i, table_data in enumerate(schema_data["tables"]):
                table_errors = self._validate_table(table_data, i)
                errors.extend(table_errors)
                
                # Check for duplicate table names
                table_name = table_data.get("name", "")
                if table_name in table_names:
                    errors.append(f"Duplicate table name: {table_name}")
                table_names.add(table_name)
            
            return len(errors) == 0, errors
            
        except Exception as e:
            errors.append(f"Schema validation error: {str(e)}")
            return False, errors
    
    def _validate_table(self, table_data: Dict, table_index: int) -> List[str]:
        """Validate a single table definition."""
        errors = []
        prefix = f"Table {table_index}"
        
        # Required fields
        if "name" not in table_data or not table_data["name"]:
            errors.append(f"{prefix}: 'name' is required")
        
        if "columns" not in table_data:
            errors.append(f"{prefix}: 'columns' is required")
            return errors
        
        if not isinstance(table_data["columns"], list):
            errors.append(f"{prefix}: 'columns' must be a list")
            return errors
        
        if len(table_data["columns"]) == 0:
            errors.append(f"{prefix}: must have at least one column")
        
        # Validate columns
        column_names = set()
        for j, column_data in enumerate(table_data["columns"]):
            column_errors = self._validate_column(column_data, table_index, j)
            errors.extend(column_errors)
            
            # Check for duplicate column names
            column_name = column_data.get("name", "")
            if column_name in column_names:
                errors.append(f"{prefix}, Column {j}: Duplicate column name: {column_name}")
            column_names.add(column_name)
        
        return errors
    
    def _validate_column(self, column_data: Dict, table_index: int, column_index: int) -> List[str]:
        """Validate a single column definition."""
        errors = []
        prefix = f"Table {table_index}, Column {column_index}"
        
        # Required fields
        if "name" not in column_data or not column_data["name"]:
            errors.append(f"{prefix}: 'name' is required")
        
        if "type" not in column_data or not column_data["type"]:
            errors.append(f"{prefix}: 'type' is required")
        
        # Validate type
        valid_types = ["string", "int", "datetime", "dynamic", "double", "bool", "long", "real"]
        column_type = column_data.get("type", "").lower()
        if column_type and column_type not in valid_types:
            errors.append(f"{prefix}: Invalid type '{column_type}'. Valid types: {', '.join(valid_types)}")
        
        return errors
    
    def parse_schema(self, schema_data: Dict, organization: Optional[str] = None) -> CustomTableSchema:
        """Parse schema data into CustomTableSchema object.
        
        Args:
            schema_data: Dictionary containing schema definition
            organization: Organization name
            
        Returns:
            CustomTableSchema object
        """
        # Add metadata
        current_time = datetime.utcnow().isoformat()
        
        # Parse tables
        tables = []
        for table_data in schema_data["tables"]:
            # Parse columns
            columns = []
            for column_data in table_data["columns"]:
                column = CustomTableColumn(
                    name=column_data["name"],
                    type=column_data["type"],
                    description=column_data.get("description"),
                    common_values=column_data.get("common_values", []),
                    required=column_data.get("required", False),
                    indexed=column_data.get("indexed", False)
                )
                columns.append(column)
            
            # Create table
            table = CustomTable(
                name=table_data["name"],
                columns=columns,
                description=table_data.get("description"),
                retentionInDays=table_data.get("retentionInDays"),
                target_formats=table_data.get("target_formats", ["kustoql"]),
                examples=table_data.get("examples", []),
                organization=organization,
                created_date=current_time,
                last_modified=current_time
            )
            tables.append(table)
        
        # Create schema
        schema = CustomTableSchema(
            organization=organization or schema_data.get("organization"),
            description=schema_data.get("description"),
            tables=tables,
            version=schema_data.get("version", "1.0"),
            created_date=current_time
        )
        
        return schema
    
    async def add_custom_tables(self, schema_file: Path, organization: str) -> Tuple[bool, str]:
        """Add custom tables from schema file.
        
        Args:
            schema_file: Path to JSON schema file
            organization: Organization name
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Read and parse schema file
            with open(schema_file, 'r', encoding='utf-8') as f:
                schema_data = json.load(f)
            
            # Validate schema
            is_valid, errors = self.validate_schema(schema_data)
            if not is_valid:
                error_msg = "Schema validation failed:\n" + "\n".join(errors)
                logger.error(error_msg)
                return False, error_msg
            
            # Parse schema
            schema = self.parse_schema(schema_data, organization)
            
            # Generate schema cards and store in ChromaDB
            collection_name = f"{self.collection_prefix}_{organization.lower()}"
            success = await self._store_custom_tables(schema, collection_name)
            
            if success:
                message = f"Successfully added {len(schema.tables)} custom tables for organization '{organization}'"
                logger.info(message)
                return True, message
            else:
                return False, "Failed to store custom tables in database"
                
        except FileNotFoundError:
            error_msg = f"Schema file not found: {schema_file}"
            logger.error(error_msg)
            return False, error_msg
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON in schema file: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error adding custom tables: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    async def _store_custom_tables(self, schema: CustomTableSchema, collection_name: str) -> bool:
        """Store custom tables in ChromaDB."""
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            # Create collection if it doesn't exist
            if not chromadb_service.collection_exists(collection_name):
                # Create the collection
                from ..services.embedding import embedding_service
                await embedding_service.initialize()
                
                # Create collection using the ChromaDB client directly
                collection = chromadb_service.client.create_collection(
                    name=collection_name,
                    metadata={
                        "description": f"Custom tables for organization {schema.organization}",
                        "created_date": schema.created_date,
                        "type": "custom_tables"
                    }
                )
                # Store collection reference
                chromadb_service.collections[collection_name] = collection
                logger.info(f"Created new collection '{collection_name}'")
            
            # Generate schema cards for each table
            documents = []
            metadatas = []
            ids = []
            
            for table in schema.tables:
                # Generate natural language description
                schema_card = self._generate_schema_card(table)
                
                documents.append(schema_card)
                metadatas.append({
                    "type": "custom_table",
                    "table_name": table.name,
                    "organization": schema.organization or "unknown",
                    "target_formats": ",".join(table.target_formats),
                    "column_count": len(table.columns),
                    "created_date": table.created_date
                })
                ids.append(f"custom_table_{table.name}_{uuid.uuid4().hex[:8]}")
            
            # Store in ChromaDB
            await chromadb_service.add_documents(
                collection_name=collection_name,
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            logger.info(f"Stored {len(documents)} custom table schema cards in collection '{collection_name}'")
            return True
            
        except Exception as e:
            logger.error(f"Error storing custom tables: {str(e)}")
            return False
    
    def _generate_schema_card(self, table: CustomTable) -> str:
        """Generate natural language schema card for a table."""
        lines = []
        
        # Table description
        lines.append(f"Table {table.name}")
        if table.description:
            lines.append(f"Description: {table.description}")
        
        # Column information
        lines.append("Columns:")
        for column in table.columns:
            column_desc = f"- {column.name} ({column.type})"
            if column.description:
                column_desc += f": {column.description}"
            if column.common_values:
                column_desc += f". Common values: {', '.join(column.common_values[:5])}"
            if column.required:
                column_desc += ". Required field"
            if column.indexed:
                column_desc += ". Indexed for fast searching"
            lines.append(column_desc)
        
        # Additional metadata
        if table.retentionInDays:
            lines.append(f"Data retention: {table.retentionInDays} days")
        
        if table.examples:
            lines.append("Example queries:")
            for example in table.examples[:3]:  # Limit to 3 examples
                lines.append(f"- {example.get('description', 'Query')}: {example.get('query', '')}")
        
        return "\n".join(lines)
    
    async def list_custom_tables(self, organization: Optional[str] = None) -> List[Dict]:
        """List custom tables for organization(s).
        
        Args:
            organization: Organization name (None for all)
            
        Returns:
            List of table information
        """
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            tables = []
            
            if organization:
                # List tables for specific organization
                collection_name = f"{self.collection_prefix}_{organization.lower()}"
                if chromadb_service.collection_exists(collection_name):
                    collection_info = chromadb_service.get_collection_info(collection_name)
                    tables.append({
                        "organization": organization,
                        "collection": collection_name,
                        "table_count": collection_info.get("count", 0),
                        "created_date": collection_info.get("created_date", "unknown")
                    })
            else:
                # List all custom table collections
                collections = chromadb_service.list_collections()
                for collection in collections:
                    if collection.startswith(self.collection_prefix):
                        org_name = collection.replace(f"{self.collection_prefix}_", "")
                        collection_info = chromadb_service.get_collection_info(collection)
                        tables.append({
                            "organization": org_name,
                            "collection": collection,
                            "table_count": collection_info.get("count", 0),
                            "created_date": collection_info.get("created_date", "unknown")
                        })
            
            return tables
            
        except Exception as e:
            logger.error(f"Error listing custom tables: {str(e)}")
            return []
    
    async def remove_custom_tables(self, organization: str) -> Tuple[bool, str]:
        """Remove custom tables for an organization.
        
        Args:
            organization: Organization name
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            collection_name = f"{self.collection_prefix}_{organization.lower()}"
            
            if not chromadb_service.collection_exists(collection_name):
                message = f"No custom tables found for organization '{organization}'"
                return False, message
            
            # Remove collection
            await chromadb_service.delete_collection(collection_name)
            
            message = f"Successfully removed custom tables for organization '{organization}'"
            logger.info(message)
            return True, message
            
        except Exception as e:
            error_msg = f"Error removing custom tables: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def get_custom_collections(self, organization: Optional[str] = None) -> List[str]:
        """Get list of custom table collection names.
        
        Args:
            organization: Organization name (None for all)
            
        Returns:
            List of collection names
        """
        try:
            collections = []
            all_collections = chromadb_service.list_collections()
            
            for collection in all_collections:
                if collection.startswith(self.collection_prefix):
                    if organization:
                        expected_name = f"{self.collection_prefix}_{organization.lower()}"
                        if collection == expected_name:
                            collections.append(collection)
                    else:
                        collections.append(collection)
            
            return collections
            
        except Exception as e:
            logger.error(f"Error getting custom collections: {str(e)}")
            return []
    
    async def search_custom_tables(
        self, 
        query: str, 
        organization: str, 
        n_results: int = 5
    ) -> List[Dict[str, Any]]:
        """Search custom tables for relevant schema information.
        
        Args:
            query: Search query
            organization: Organization name
            n_results: Maximum number of results
            
        Returns:
            List of search results
        """
        try:
            # Initialize ChromaDB service first
            await chromadb_service.initialize()
            
            collection_name = f"{self.collection_prefix}_{organization.lower()}"
            
            if not chromadb_service.collection_exists(collection_name):
                logger.debug(f"No custom tables found for organization '{organization}'")
                return []
            
            # Perform semantic search on custom table collection
            results = await chromadb_service.query_collection(
                collection_name=collection_name,
                query_text=query,
                n_results=n_results
            )
            
            # Format results for hybrid retrieval
            formatted_results = []
            if results and "documents" in results:
                for i, doc in enumerate(results["documents"][0]):
                    metadata = results.get("metadatas", [[]])[0]
                    metadata_item = metadata[i] if i < len(metadata) else {}
                    
                    formatted_results.append({
                        "document": doc,
                        "metadata": metadata_item,
                        "source": "custom_tables",
                        "organization": organization,
                        "score": results.get("distances", [[1.0]])[0][i] if results.get("distances") else 1.0
                    })
            
            logger.debug(f"Found {len(formatted_results)} custom table results for organization '{organization}'")
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error searching custom tables: {str(e)}")
            return []

    async def get_available_organizations(self) -> List[str]:
        """Get list of organizations that have custom tables.
        
        Returns:
            List of organization names
        """
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            organizations = []
            all_collections = chromadb_service.list_collections()
            
            for collection in all_collections:
                if collection.startswith(self.collection_prefix + "_"):
                    # Extract organization name from collection name
                    org_name = collection[len(self.collection_prefix) + 1:]
                    organizations.append(org_name)
            
            return organizations
            
        except Exception as e:
            logger.error(f"Error getting available organizations: {str(e)}")
            return []
    
    async def auto_detect_organization(self, rule_content: str = "") -> Optional[str]:
        """Auto-detect the best organization to use based on available custom tables.
        
        Args:
            rule_content: Optional rule content for context-based detection
            
        Returns:
            Organization name or None if no custom tables available
        """
        try:
            organizations = await self.get_available_organizations()
            
            if not organizations:
                return None
            
            # If only one organization, use it
            if len(organizations) == 1:
                logger.info(f"Auto-detected organization: {organizations[0]}")
                return organizations[0]
            
            # If multiple organizations, try to pick the best match
            # For now, just use the first one, but this could be enhanced with
            # rule content analysis or user preferences
            selected_org = organizations[0]
            logger.info(f"Multiple organizations available {organizations}, using: {selected_org}")
            return selected_org
            
        except Exception as e:
            logger.error(f"Error auto-detecting organization: {str(e)}")
            return None


# Global service instance
custom_table_service = CustomTableService() 