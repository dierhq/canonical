#!/usr/bin/env python3
"""
Test script for Foundation-Sec-8B integration in Canonical.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.canonical.services.llm import llm_service
from src.canonical.core.models import TargetFormat


async def test_foundation_sec_initialization():
    """Test that Foundation-Sec-8B can be initialized."""
    print("🔧 Testing Foundation-Sec-8B initialization...")
    
    try:
        await llm_service.initialize()
        print(f"✅ Successfully initialized LLM service")
        print(f"📊 Current model: {llm_service.current_model}")
        print(f"🎯 Primary model initialized: {llm_service.primary_initialized}")
        print(f"🔄 Fallback model initialized: {llm_service.fallback_initialized}")
        
        if llm_service.current_model == "foundation-sec-8b":
            print("🚀 Foundation-Sec-8B is active!")
            capabilities = llm_service.model_capabilities.get("foundation-sec-8b", {})
            print(f"🛡️ Cybersecurity specialized: {capabilities.get('cybersecurity_specialized', False)}")
            print(f"🎯 MITRE ATT&CK knowledge: {capabilities.get('mitre_attack_knowledge', False)}")
        elif llm_service.current_model == "qwen":
            print("⚠️ Using Qwen fallback model")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to initialize LLM service: {e}")
        return False


async def test_cybersecurity_knowledge():
    """Test Foundation-Sec-8B's cybersecurity knowledge."""
    print("\n🔍 Testing cybersecurity knowledge...")
    
    cybersec_prompt = """What is CVE-2021-44228 and what MITRE ATT&CK technique does it relate to?"""
    
    try:
        response = await llm_service.generate_response(
            cybersec_prompt, 
            max_tokens=200,
            use_cybersec_optimization=True
        )
        print(f"✅ Cybersecurity knowledge test response:")
        print(f"📝 {response[:300]}...")
        return True
        
    except Exception as e:
        print(f"❌ Cybersecurity knowledge test failed: {e}")
        return False


async def test_sigma_rule_conversion():
    """Test Sigma rule conversion with Foundation-Sec-8B."""
    print("\n🔄 Testing Sigma rule conversion...")
    
    test_sigma_rule = """
title: Suspicious PowerShell Execution
status: experimental
description: Detects suspicious PowerShell command execution with encoded commands
author: Test
date: 2025/01/01
detection:
    selection:
        Image|endswith: 'powershell.exe'
        CommandLine|contains: 'EncodedCommand'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1059.001
"""
    
    try:
        result = await llm_service.convert_sigma_rule(
            sigma_rule=test_sigma_rule,
            target_format=TargetFormat.KUSTOQL,
            context={"mitre_techniques": ["T1059.001"]}
        )
        
        print(f"✅ Conversion result:")
        print(f"🎯 Success: {result.get('success', False)}")
        print(f"📊 Confidence: {result.get('confidence_score', 0.0)}")
        print(f"📝 Converted rule:")
        print(result.get('target_rule', 'No rule generated')[:200] + "...")
        
        return result.get('success', False)
        
    except Exception as e:
        print(f"❌ Sigma rule conversion failed: {e}")
        return False


async def test_rule_explanation():
    """Test rule explanation capability."""
    print("\n📖 Testing rule explanation...")
    
    test_rule = "SecurityEvent | where EventID == 4688 | where NewProcessName contains 'powershell.exe'"
    
    try:
        explanation = await llm_service.explain_rule(test_rule, "KustoQL")
        print(f"✅ Rule explanation:")
        print(f"📝 {explanation[:300]}...")
        return True
        
    except Exception as e:
        print(f"❌ Rule explanation failed: {e}")
        return False


async def test_model_fallback():
    """Test fallback mechanism."""
    print("\n🔄 Testing model fallback mechanism...")
    
    # Force an error to test fallback
    original_primary = llm_service.primary_initialized
    llm_service.primary_initialized = False
    
    try:
        response = await llm_service.generate_response(
            "Test fallback response", 
            max_tokens=50,
            use_cybersec_optimization=False
        )
        print(f"✅ Fallback mechanism works:")
        print(f"📝 Response: {response[:100]}...")
        
        # Restore original state
        llm_service.primary_initialized = original_primary
        return True
        
    except Exception as e:
        print(f"❌ Fallback test failed: {e}")
        # Restore original state
        llm_service.primary_initialized = original_primary
        return False


async def main():
    """Run all Foundation-Sec-8B tests."""
    print("🧪 Foundation-Sec-8B Integration Test Suite")
    print("=" * 50)
    
    tests = [
        ("Initialization", test_foundation_sec_initialization),
        ("Cybersecurity Knowledge", test_cybersecurity_knowledge),
        ("Sigma Rule Conversion", test_sigma_rule_conversion),
        ("Rule Explanation", test_rule_explanation),
        ("Model Fallback", test_model_fallback)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{'🧪 ' + test_name:-<45}")
        success = await test_func()
        results.append((test_name, success))
    
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{test_name:<30} {status}")
        if success:
            passed += 1
    
    print(f"\n🎯 Overall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🚀 Foundation-Sec-8B integration is working perfectly!")
    elif passed > 0:
        print("⚠️ Foundation-Sec-8B integration is partially working")
    else:
        print("❌ Foundation-Sec-8B integration needs attention")
    
    return passed == len(results)


if __name__ == "__main__":
    # Set environment variables for testing
    os.environ.setdefault("USE_FOUNDATION_SEC", "true")
    os.environ.setdefault("ENABLE_MODEL_FALLBACK", "true")
    os.environ.setdefault("LLM_DEVICE", "auto")
    
    success = asyncio.run(main())
    sys.exit(0 if success else 1) 