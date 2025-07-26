'use client';

import { Loader2 } from 'lucide-react';

interface LoadingIndicatorProps {
  currentStep: number;
  steps: string[];
  className?: string;
}

export default function LoadingIndicator({ currentStep, steps, className = '' }: LoadingIndicatorProps) {
  return (
    <div className={`flex items-center justify-center ${className}`}>
      <div className="text-center">
        <Loader2 className="w-8 h-8 animate-spin text-gray-600 mx-auto mb-3" />
        <div className="space-y-2">
          <p className="text-sm text-gray-600 font-medium">
            {steps[currentStep % steps.length]}
          </p>
          <div className="flex space-x-1 justify-center">
            {steps.map((_, index) => (
              <div
                key={index}
                className={`w-2 h-2 rounded-full transition-colors ${
                  index === currentStep % steps.length
                    ? 'bg-gray-600'
                    : index < currentStep % steps.length
                    ? 'bg-gray-300'
                    : 'bg-gray-100'
                }`}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
} 