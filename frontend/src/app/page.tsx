'use client';

import PlaygroundTab from '@/components/PlaygroundTab';

export default function Home() {

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
                          <div className="flex items-center">
                <h1 className="text-2xl font-semibold text-gray-900">
                  Canonical Converter
                </h1>
              </div>
            <div className="text-sm text-gray-600">
              Powered by DEIR
            </div>
          </div>
        </div>
      </header>

              {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <PlaygroundTab />
        </main>
    </div>
  );
}
