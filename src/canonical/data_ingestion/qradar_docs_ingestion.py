"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Data ingestion script for QRadar documentation and knowledge base.
"""

import asyncio
import json
import re
from typing import List, Dict, Any, Optional
from loguru import logger
from pathlib import Path

from ..core.config import settings
from ..services.chromadb import chromadb_service


class QRadarDocsIngestion:
    """QRadar documentation ingestion service."""
    
    def __init__(self):
        """Initialize the QRadar docs ingestion service."""
        self.collection_name = settings.qradar_docs_collection
    
    async def ingest_qradar_blog_docs(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Ingest QRadar documentation from IBM blog post.
        
        Args:
            force_refresh: Whether to force refresh the collection
            
        Returns:
            Ingestion statistics
        """
        logger.info("Starting QRadar documentation ingestion from IBM blog post")
        
        try:
            # Initialize ChromaDB service
            await chromadb_service.initialize()
            
            # Clear collection if force refresh
            if force_refresh:
                logger.info("Force refresh enabled, clearing existing collection")
                await chromadb_service.delete_collection(self.collection_name)
                
                # Recreate the collection
                collection = chromadb_service.client.get_or_create_collection(
                    name=self.collection_name,
                    metadata={"description": "QRadar documentation and knowledge base"}
                )
                chromadb_service.collections[self.collection_name] = collection
                logger.info(f"Collection '{self.collection_name}' recreated")
            
            # QRadar documentation content from IBM blog post
            qradar_docs = self._get_qradar_documentation()
            
            # Process and ingest documents
            documents = []
            metadatas = []
            ids = []
            
            for doc in qradar_docs:
                documents.append(doc["content"])
                metadatas.append(doc["metadata"])
                ids.append(doc["id"])
            
            # Add documents to ChromaDB
            if documents:
                await chromadb_service.add_documents(
                    collection_name=self.collection_name,
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
            
            stats = {
                "total_documents": len(documents),
                "successful": len(documents),
                "failed": 0,
                "collection": self.collection_name
            }
            
            logger.info(f"QRadar documentation ingestion completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"QRadar documentation ingestion failed: {e}")
            raise
    
    def _get_qradar_documentation(self) -> List[Dict[str, Any]]:
        """Get QRadar documentation content from IBM blog post."""
        
        docs = []
        
        # Document 1: Custom Rules Engine Overview
        docs.append({
            "id": "qradar_cre_overview",
            "content": """
            The Custom Rules Engine (CRE) is a flexible engine for correlating events, flow, and offense data. 
            The correlation takes place through a series of out-of-the-box and user-created rules that get 
            evaluated against the events and flows as they pass in near-real time through the QRadar pipeline.
            
            The CRE processes rules in a specific order:
            1. First rule loaded is FalsePositive: False Positive Rules and Building Blocks
            2. Then other Building Blocks and their dependencies
            3. Rules are loaded at the end
            
            If an offense is not firing or any response is not taken, the first thing to look at is if 
            the event is not caught by a false positive Building Block.
            """,
            "metadata": {
                "title": "QRadar Custom Rules Engine Overview",
                "source": "IBM QRadar Blog",
                "category": "Architecture",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 2: Rule Types
        docs.append({
            "id": "qradar_rule_types",
            "content": """
            QRadar has two main types of rules:
            
            1. Rules: A group of tests that can trigger an action if specific conditions are met. 
               Rules are configured to capture and respond to specific sequence of events, flows, or offenses 
               to trigger an action such as sending an email notification or syslog message.
               
               Inside the rules category, you can find:
               - Traditional correlation rules
               - Anomaly rules (special type requiring dedicated handling)
            
            2. Building Blocks: A rule with no action or response. The only action a building block takes 
               is to tag the events and flow records when it matches the series of tests. They are used as 
               a common variable in multiple rules and to build complex rules or logic.
               
               Important: To be "enabled", a building block needs to be referenced in a rule. If no rule 
               is referring to a building block then the building block will not be executed.
            """,
            "metadata": {
                "title": "QRadar Rule Types",
                "source": "IBM QRadar Blog",
                "category": "Rule Types",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 3: Test Evaluation Order
        docs.append({
            "id": "qradar_test_evaluation",
            "content": """
            QRadar tests can be separated into two types:
            
            1. Stateless Test: Any test that can make a true or false assertion with a single event or flow. 
               QRadar needs only the one event or flow to consider the test to be a success or a failure.
               Examples: "when the event(s) occur on any of Wednesday, Friday"
            
            2. Stateful Test: When QRadar needs more than one event or flow, occurring in a specific timeframe, 
               to determine if the situation is happening.
               Examples: 
               - "when the username changes more than 3 times within 60 minutes on a single host"
               - "when the hostname changes more than 2 times within 8 hours on a single host"
            
            QRadar's Custom Rules Engine (CRE) always processes the Stateless tests first, in order. 
            Then the Stateful tests last, regardless of their order in the rule.
            
            Warning: Counters are reset when the ecs-ep service restarts or when the rule is saved. 
            For long term monitoring, one option is to use Reference Data.
            """,
            "metadata": {
                "title": "QRadar Test Evaluation Order",
                "source": "IBM QRadar Blog",
                "category": "Rule Processing",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 4: Rule Categories
        docs.append({
            "id": "qradar_rule_categories",
            "content": """
            There are four categories of QRadar rule types:
            
            1. Event Rules: Test against incoming log source data that is processed in real time by the 
               QRadar Event Processor. You can create an event rule to detect one single event, or events 
               sequences. Example: monitor for unsuccessful login attempts, access multiple hosts, or a 
               reconnaissance event followed by an exploit.
               
            2. Flow Rules: Test against incoming flow data that is processed by the QRadar Flow Processor. 
               You can create a flow rule to detect one single flow, or flows sequences.
               
            3. Common Rules: Test against both event and flow data. For example, you can create a common 
               rule to detect events and flows that have a specific source IP address.
               
            4. Offense Rules: Test the parameters of offenses to trigger more responses. For example, 
               you can trigger a response when new events are added, or schedule offenses reassessment 
               at a specific date and time. You can also monitor offense magnitude or number of 
               contribution for a specific attribute.
            
            It is common for event, flow, and common rules to create offenses as a response.
            It is common for offense rules to email a notification as a response.
            """,
            "metadata": {
                "title": "QRadar Rule Categories",
                "source": "IBM QRadar Blog",
                "category": "Rule Categories",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 5: Negative Tests
        docs.append({
            "id": "qradar_negative_tests",
            "content": """
            Negative tests are a special case in QRadar rules. They monitor the absence of events, 
            so they are not activated by an incoming event, but rather when an event is not seen 
            in a specified timeframe.
            
            Negative tests are particularly useful for:
            - Monitoring for missing heartbeat events
            - Detecting when expected security events don't occur
            - Identifying gaps in log collection
            - Alerting on missing system health indicators
            
            These tests help ensure comprehensive monitoring by detecting what should be happening 
            but isn't, which is often as important as detecting malicious activity.
            """,
            "metadata": {
                "title": "QRadar Negative Tests",
                "source": "IBM QRadar Blog",
                "category": "Rule Types",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 6: Rule Actions and Responses
        docs.append({
            "id": "qradar_rule_actions",
            "content": """
            QRadar rules can have various actions and responses:
            
            1. Dispatch New Event: It is possible to create a new event as Rule Response. 
               For example, when QRadar detects Firewall Deny events 1,000 times, it generates 
               a new event called "Scan Detected".
               
               You have options to affect the offense naming:
               - Totally replace the offense description
               - Partially contribute to the name (original description preserved, new content added)
               - Not affect the offense naming at all
            
            2. Response Limiter: Used to limit the number of rule responses a rule will trigger 
               for a particular "object" (an IP, a username, etc).
               
               Key points about response limiter:
               - Applies to the "Rule Response" section only, not the "Rule Action" section
               - An offense will include all detected events (if the box is checked)
               - CRE will only generate one extra event per time period per object
               - Recommended to use response limiter to avoid flooding when sending email or notifications
               - Usually follows the same logic as offense indexing
            """,
            "metadata": {
                "title": "QRadar Rule Actions and Responses",
                "source": "IBM QRadar Blog",
                "category": "Rule Actions",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 7: Rule Updates and Origins
        docs.append({
            "id": "qradar_rule_updates",
            "content": """
            QRadar rules have different origins that affect how they are updated:
            
            1. System Rules: These rules are provided by IBM. They are updated during QRadar 
               upgrade or when you install content extensions.
               
            2. User Rules: These rules are created by you. IBM doesn't touch the content of these rules.
            
            3. Modified Rules: These rules have originally been provided by IBM but have been 
               modified on your side.
            
            Protection Mechanism for Modified Rules:
            When you save a rule that has been provided by IBM, the original version is copied 
            and hidden, and what you're updating is only the copy of the rule. This means:
            - All updates from IBM are applied to the hidden rule
            - All your changes are applied to your copy
            - You can revert to IBM's latest version at any time by clicking "Revert Rule"
            
            This prevents IBM from overriding your customizations while still allowing you 
            to benefit from IBM's updates.
            """,
            "metadata": {
                "title": "QRadar Rule Updates and Origins",
                "source": "IBM QRadar Blog",
                "category": "Rule Management",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 8: Rule Performance Best Practices
        docs.append({
            "id": "qradar_performance_best_practices",
            "content": """
            To build efficient QRadar rules, you must reduce the scope of events and flows tested, 
            and short-circuit the series of tests as soon as possible with fast wide checks.
            
            Test Execution Logic:
            - Each test gives a positive or negative result
            - When a negative result is encountered, QRadar will not execute any further rule conditions
            - This utilizes less CPU to process events (short-circuit evaluation)
            
            Examples:
            - "test1 and test2": CRE only executes test2 if test1 evaluates to true
            - "not test1 and test2": CRE only executes test2 if test1 evaluates to false
            - "test1 and not test2 and test3": CRE executes test2 only if test1 is true, 
              and test3 only if test1 is true and test2 is false
            
            Test Performance Hierarchy (Fast to Slow):
            
            1. FAST TESTS:
               - Building Blocks (cached in memory)
               - Custom Properties (especially numerical: Boolean, Equality, Greater-than, Less-than)
               - Normalized Properties
               - Identity Information (username, IP, hostname, MAC, etc.)
               - Event Information (Event Name, Username, Relevance, Severity, etc.)
               - Source/Destination Information (IPs, Ports, MACs, etc.)
            
            2. MEDIUM TESTS (context-dependent):
               - AQL tests (can be very fast or very slow depending on usage)
               - Reference Data (depends on scope and data volume)
            
            3. SLOW TESTS:
               - Payload contains
               - Match (regular expression)
            
            Best Practice: Use payload match and regexes only after filtering the maximum 
            number of events with faster tests.
            """,
            "metadata": {
                "title": "QRadar Rule Performance Best Practices",
                "source": "IBM QRadar Blog",
                "category": "Performance",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 9: QRadar Test Types for Event Rules
        docs.append({
            "id": "qradar_event_rule_tests",
            "content": """
            QRadar Event Rules have 12 types of tests available:
            
            1. Event Information Tests:
               - Event Name, Username, Relevance, Severity, Credibility
               - Event Category, Log Source Time
               
            2. Source and Destination Information Tests:
               - Source IP, Destination IP, Source Port, Destination Port
               - Source MAC, Destination MAC, Source IPv6, Destination IPv6
               - Pre/Post NAT Source/Destination IP and Port information
               
            3. Identity Information Tests:
               - Identity username, Identity IP, Identity Host Name
               - Identity MAC, Identity Group Name, Identity Extended Field
               - Identity NetBios Name
               
            4. Additional Information Tests:
               - Protocol, Log Source
               
            5. Custom Properties Tests:
               - Numerical tests (Boolean, Equality, Greater-than, Less-than)
               - Alphanumerical comparisons (Equality, Subset)
               
            6. Building Blocks Tests:
               - References to existing building blocks
               
            7. Normalized Properties Tests:
               - Standardized field mappings
               
            8. Payload Tests:
               - Payload contains (slow)
               - Regular expression matching (slow)
               
            9. Reference Data Tests:
               - Lookups against reference data sets
               
            10. AQL Tests:
                - Custom AQL queries
                
            11. Time-based Tests:
                - Time window evaluations
                
            12. Statistical Tests:
                - Count-based evaluations
            """,
            "metadata": {
                "title": "QRadar Event Rule Test Types",
                "source": "IBM QRadar Blog",
                "category": "Event Rules",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 10: QRadar Flow Rule Tests
        docs.append({
            "id": "qradar_flow_rule_tests",
            "content": """
            QRadar Flow Rules have 11 types of tests available for testing against 
            incoming flow data processed by the QRadar Flow Processor:
            
            1. Flow Source/Destination Information:
               - Source IP, Destination IP
               - Source Port, Destination Port
               - Source MAC, Destination MAC
               
            2. Flow Protocol Information:
               - Protocol type and details
               
            3. Flow Timing Information:
               - Flow start time, end time, duration
               
            4. Flow Volume Information:
               - Bytes transferred, packet counts
               
            5. Flow Direction Information:
               - Inbound, outbound, internal flows
               
            6. Flow Application Information:
               - Application identification and classification
               
            7. Flow Geographic Information:
               - Geographic location of source/destination
               
            8. Flow Custom Properties:
               - User-defined flow properties
               
            9. Flow Building Blocks:
               - References to flow-specific building blocks
               
            10. Flow Reference Data:
                - Lookups against flow-related reference data
                
            11. Flow AQL Tests:
                - Custom AQL queries for flow data
            
            Flow rules are commonly used to detect network-based threats, 
            unusual traffic patterns, and data exfiltration attempts.
            """,
            "metadata": {
                "title": "QRadar Flow Rule Test Types",
                "source": "IBM QRadar Blog",
                "category": "Flow Rules",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 11: QRadar Common Rules
        docs.append({
            "id": "qradar_common_rules",
            "content": """
            QRadar Common Rules test against both event and flow data simultaneously. 
            They have 10 groups of tests available:
            
            1. Common IP Information:
               - Source IP, Destination IP (works for both events and flows)
               - IP reputation and geographic information
               
            2. Common Port Information:
               - Source Port, Destination Port (applicable to both data types)
               
            3. Common Protocol Information:
               - Protocol identification across events and flows
               
            4. Common Time Information:
               - Timestamp correlations between events and flows
               
            5. Common Identity Information:
               - User identity across both event and flow data
               
            6. Common Custom Properties:
               - Properties that apply to both events and flows
               
            7. Common Building Blocks:
               - Building blocks that work with both data types
               
            8. Common Reference Data:
               - Reference data applicable to both events and flows
               
            9. Common AQL Tests:
               - AQL queries that span both event and flow data
               
            10. Common Statistical Tests:
                - Statistical analysis across both data types
            
            Common rules are particularly useful for:
            - Correlating network activity with log events
            - Detecting multi-stage attacks that span both domains
            - Creating comprehensive detection coverage
            
            Example use case: Detect events and flows that have a specific source IP address, 
            combining log-based authentication events with network flow data.
            """,
            "metadata": {
                "title": "QRadar Common Rule Test Types",
                "source": "IBM QRadar Blog",
                "category": "Common Rules",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        # Document 12: QRadar Offense Rules
        docs.append({
            "id": "qradar_offense_rules",
            "content": """
            QRadar Offense Rules test the parameters of offenses to trigger additional responses. 
            They have 5 groups of tests available:
            
            1. Offense Magnitude Tests:
               - Monitor offense magnitude changes
               - Trigger responses based on severity escalation
               
            2. Offense Contribution Tests:
               - Monitor number of contributions for specific attributes
               - Detect when offense patterns change
               
            3. Offense Timing Tests:
               - Schedule offense reassessment at specific date and time
               - Monitor offense age and lifecycle
               
            4. Offense Event Addition Tests:
               - Trigger responses when new events are added to offenses
               - Monitor offense growth patterns
               
            5. Offense Status Tests:
               - Monitor offense status changes (open, closed, hidden)
               - Trigger workflows based on status transitions
            
            Common Use Cases for Offense Rules:
            - Email notifications when offense severity increases
            - Automatic ticket creation for high-magnitude offenses
            - Escalation procedures for long-running offenses
            - Integration with external security orchestration platforms
            - Automated response workflows
            
            Offense rules are commonly used to send email notifications as responses, 
            but can also trigger other automated responses like:
            - SIEM integration calls
            - Security orchestration platform notifications
            - Automated incident response procedures
            - Compliance reporting triggers
            """,
            "metadata": {
                "title": "QRadar Offense Rule Test Types",
                "source": "IBM QRadar Blog",
                "category": "Offense Rules",
                "url": "https://community.ibm.com/community/user/blogs/gladys-koskas1/2022/09/29/everything-you-need-to-know-about-qradar-rules"
            }
        })
        
        return docs


# Global instance
qradar_docs_ingestion = QRadarDocsIngestion() 