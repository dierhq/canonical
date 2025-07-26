'use client';

import { useState } from 'react';
import { ChevronDown, Play, Copy, Loader2, Check } from 'lucide-react';
import { Listbox, Transition } from '@headlessui/react';
import { Fragment } from 'react';
import axios from 'axios';
import LoadingIndicator from './LoadingIndicator';

const sourceFormats = [
  { value: 'sigma', label: 'Sigma' },
  { value: 'qradar', label: 'QRadar AQL' },
  { value: 'kibanaql', label: 'KibanaQL' },
];

const targetFormats = [
  { value: 'kustoql', label: 'KustoQL (Azure Sentinel)' },
  { value: 'kibanaql', label: 'KibanaQL (Elastic)' },
  { value: 'eql', label: 'EQL (Event Query Language)' },
  { value: 'qradar', label: 'QRadar AQL' },
  { value: 'spl', label: 'Splunk SPL' },
  { value: 'sigma', label: 'Sigma' },
];

const sampleRules = {
  sigma: `title: Windows PowerShell Execution
id: a6a39bdb-935c-4f0a-ab77-35f4bbf44b41
status: experimental
description: Detects PowerShell execution
author: Canonical
date: 2025/01/01
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4103
        Message|contains: 'powershell'
    condition: selection
fields:
    - Image
    - CommandLine
falsepositives:
    - Administrative scripts
level: medium`,
  qradar: `SELECT DATEFORMAT(startTime,'yyyy-MM-dd HH:mm:ss') as Event_Time, 
       sourceIP, destinationIP, username, 
       "EventName" as Event_Name
FROM events 
WHERE ("EventName" ILIKE '%PowerShell%' OR "Process Name" ILIKE '%powershell%')
  AND startTime > LAST 24 HOURS
ORDER BY startTime DESC`,
  kibanaql: `{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "event.category": "process"
          }
        },
        {
          "match": {
            "process.name": "powershell.exe"
          }
        }
      ],
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-24h"
            }
          }
        }
      ]
    }
  }
}`
};

interface ConversionResponse {
  success: boolean;
  target_rule: string;
  confidence_score: number;
  explanation: string;
  mitre_techniques: string[];
  field_mappings: Record<string, string>;
  conversion_notes: string[];
  error_message?: string;
  metadata: Record<string, any>;
}

function classNames(...classes: string[]) {
  return classes.filter(Boolean).join(' ');
}

const loadingSteps = [
  'Parsing source rule...',
  'Analyzing rule structure...',
  'Retrieving conversion context...',
  'Mapping fields and operators...',
  'Generating target rule...',
  'Validating output...',
  'Calculating confidence score...'
];

export default function PlaygroundTab() {
  const [sourceFormat, setSourceFormat] = useState(sourceFormats[0]);
  const [targetFormat, setTargetFormat] = useState(targetFormats[0]);
  const [sourceRule, setSourceRule] = useState('');
  const [currentLoadingStep, setCurrentLoadingStep] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<ConversionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isCopied, setIsCopied] = useState(false);

  const convertRule = async ({ source, target, rule }: { source: string; target: string; rule: string }) => {
    setIsLoading(true);
    setError(null);
    
    // Simulate loading steps for better UX
    const stepInterval = setInterval(() => {
      setCurrentLoadingStep(prev => (prev + 1) % loadingSteps.length);
    }, 800);

    try {
      const response = await axios.post<ConversionResponse>('/api/convert', {
        source_rule: rule,
        source_format: source,
        target_format: target,
      });
      clearInterval(stepInterval);
      setCurrentLoadingStep(0);
      if (response.data.success) {
        setResult(response.data);
      } else {
        // Handle failed conversion from backend
        setError(response.data.error_message || 'Conversion failed');
        setResult(null);
      }
    } catch (error: any) {
      clearInterval(stepInterval);
      setCurrentLoadingStep(0);
      if (error?.response?.data?.detail) {
        setError(error.response.data.detail);
      } else if (error?.response?.data?.error_message) {
        setError(error.response.data.error_message);
      } else if (error?.message) {
        setError(error.message);
      } else {
        setError('Conversion failed');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleConvert = () => {
    if (!sourceRule.trim()) return;
    
    convertRule({
      source: sourceFormat.value,
      target: targetFormat.value,
      rule: sourceRule,
    });
  };

  const loadSample = () => {
    setSourceRule(sampleRules[sourceFormat.value as keyof typeof sampleRules] || '');
  };

  const copyResult = async () => {
    if (result?.target_rule) {
      await navigator.clipboard.writeText(result.target_rule);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 3000); // Reset after 3 seconds
    }
  };

    return (
    <div className="space-y-6">
      {/* Rule Format Selection */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 shadow-sm">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Configuration</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Source Format
            </label>
            <Listbox value={sourceFormat} onChange={setSourceFormat}>
              <div className="relative">
                <Listbox.Button className="relative w-full cursor-default rounded-lg bg-white py-3 pl-3 pr-10 text-left shadow-sm border border-gray-300 focus:outline-none focus:ring-0 focus:border-gray-400 hover:border-gray-400 transition-colors">
                  <span className="block truncate text-sm font-medium text-gray-900">{sourceFormat.label}</span>
                  <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
                    <ChevronDown className="h-4 w-4 text-gray-500" aria-hidden="true" />
                  </span>
                </Listbox.Button>
                <Transition
                  as={Fragment}
                  leave="transition ease-in duration-100"
                  leaveFrom="opacity-100"
                  leaveTo="opacity-0"
                >
                  <Listbox.Options className="absolute z-10 mt-1 max-h-60 w-full overflow-auto rounded-lg bg-white py-1 text-sm shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none border border-gray-200">
                    {sourceFormats.map((format) => (
                      <Listbox.Option
                        key={format.value}
                        className={({ active }) =>
                          classNames(
                            'relative cursor-default select-none py-2 pl-3 pr-4',
                            active ? 'bg-gray-50 text-gray-900' : 'text-gray-900'
                          )
                        }
                        value={format}
                      >
                        {({ selected }) => (
                          <span className={classNames('block truncate', selected ? 'font-semibold' : 'font-normal')}>
                            {format.label}
                          </span>
                        )}
                      </Listbox.Option>
                    ))}
                  </Listbox.Options>
                </Transition>
              </div>
            </Listbox>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Target Format
            </label>
            <Listbox value={targetFormat} onChange={setTargetFormat}>
              <div className="relative">
                <Listbox.Button className="relative w-full cursor-default rounded-lg bg-white py-3 pl-3 pr-10 text-left shadow-sm border border-gray-300 focus:outline-none focus:ring-0 focus:border-gray-400 hover:border-gray-400 transition-colors">
                  <span className="block truncate text-sm font-medium text-gray-900">{targetFormat.label}</span>
                  <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
                    <ChevronDown className="h-4 w-4 text-gray-500" aria-hidden="true" />
                  </span>
                </Listbox.Button>
                <Transition
                  as={Fragment}
                  leave="transition ease-in duration-100"
                  leaveFrom="opacity-100"
                  leaveTo="opacity-0"
                >
                  <Listbox.Options className="absolute z-10 mt-1 max-h-60 w-full overflow-auto rounded-lg bg-white py-1 text-sm shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none border border-gray-200">
                    {targetFormats.map((format) => (
                      <Listbox.Option
                        key={format.value}
                        className={({ active }) =>
                          classNames(
                            'relative cursor-default select-none py-2 pl-3 pr-4',
                            active ? 'bg-gray-50 text-gray-900' : 'text-gray-900'
                          )
                        }
                        value={format}
                      >
                        {({ selected }) => (
                          <span className={classNames('block truncate', selected ? 'font-semibold' : 'font-normal')}>
                            {format.label}
                          </span>
                        )}
                      </Listbox.Option>
                    ))}
                  </Listbox.Options>
                </Transition>
              </div>
            </Listbox>
          </div>
        </div>
      </div>

      {/* Input and Output Section - Side by Side */}
      <div className="grid grid-cols-2 gap-6">
        {/* Source Rule Section */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900">Source Rule</h3>
            <div className="flex items-center space-x-2">
              <button
                onClick={loadSample}
                className="text-sm text-gray-600 hover:text-gray-900 font-medium transition-colors px-3 py-1 rounded-md border border-gray-300 hover:border-gray-400 hover:bg-gray-50"
              >
                Load Sample
              </button>
              <button
                onClick={handleConvert}
                disabled={!sourceRule.trim() || isLoading}
                className="flex items-center space-x-1 text-sm text-gray-600 hover:text-gray-900 font-medium transition-colors px-3 py-1 rounded-md border border-gray-300 hover:border-gray-400 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                <span>Convert Rule</span>
              </button>
            </div>
          </div>
          <div className="relative">
            <textarea
              className="w-full p-4 font-mono text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-500 focus:border-gray-500 resize-none bg-white shadow-sm"
              style={{ height: '80vh', minHeight: '600px' }}
              placeholder="Paste your source rule here..."
              value={sourceRule}
              onChange={(e) => setSourceRule(e.target.value)}
            />
            {sourceRule && (
              <div className="absolute top-2 right-2 bg-white bg-opacity-90 px-2 py-1 rounded text-xs text-gray-500">
                {sourceRule.split('\n').length} lines
              </div>
            )}
          </div>
        </div>

        {/* Target Rule Section */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900">Converted Rule</h3>
            {result?.target_rule && (
              <button
                onClick={copyResult}
                className={`flex items-center space-x-1 text-sm font-medium transition-colors px-3 py-1 rounded-md border ${
                  isCopied
                    ? 'text-green-600 border-green-200 bg-green-50'
                    : 'text-gray-600 hover:text-gray-900 border-gray-300 hover:border-gray-400 hover:bg-gray-50'
                }`}
              >
                {isCopied ? (
                  <Check className="w-4 h-4" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
                <span>{isCopied ? 'Copied' : 'Copy'}</span>
              </button>
            )}
          </div>
          
          <div className="relative">
            <textarea
              className="w-full p-4 font-mono text-sm border border-gray-300 rounded-lg bg-gray-50 resize-none shadow-sm"
              style={{ height: '80vh', minHeight: '600px' }}
              readOnly
              value={
                isLoading
                  ? `// Converting... ${loadingSteps[currentLoadingStep]}`
                  : result?.target_rule || ''
              }
              placeholder="Converted rule will appear here..."
            />
            
            {isLoading && (
              <div className="absolute inset-0 bg-white bg-opacity-75 flex items-center justify-center rounded-lg">
                <LoadingIndicator 
                  currentStep={currentLoadingStep}
                  steps={loadingSteps}
                />
              </div>
            )}
            
            {result?.confidence_score && (
              <div className="absolute top-2 right-2 bg-white bg-opacity-90 px-2 py-1 rounded text-xs">
                <span className={`font-medium ${
                  result.confidence_score >= 0.8
                    ? 'text-green-600'
                    : result.confidence_score >= 0.6
                    ? 'text-yellow-600'
                    : 'text-red-600'
                }`}>
                  {(result.confidence_score * 100).toFixed(0)}% confidence
                </span>
              </div>
            )}
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-sm text-red-600">
                <strong>Error:</strong> {error}
              </p>
              {error.includes('Invalid YAML') && sourceFormat.value === 'sigma' && (
                <p className="text-xs text-red-500 mt-1">
                  💡 Tip: If you're converting a QRadar rule, make sure to select "QRadar AQL" as the source format.
                </p>
              )}
            </div>
          )}
        </div>
      </div>


    </div>
  );
} 