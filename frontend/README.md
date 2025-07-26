# Canonical SIEM Rule Converter - Frontend

A modern React/Next.js web interface for the Canonical SIEM rule conversion system. Built with TypeScript, Tailwind CSS, and following OpenAI's design principles.

## Features

### 🎮 Playground Tab
- **Interactive Rule Conversion**: Convert single rules between different SIEM formats
- **Real-time Format Detection**: Auto-detect source format or manually select
- **Sample Rules**: Pre-loaded examples for testing different formats
- **Live Conversion Feedback**: See LangGraph node processing steps during conversion
- **Confidence Scoring**: AI-generated confidence levels for each conversion
- **MITRE ATT&CK Integration**: Automatic technique mapping and display

### 📊 Bulk Upload Tab
- **Drag & Drop Interface**: Upload multiple rule files (JSON, ZIP, TXT, YAML)
- **Queue Management**: See upload progress and processing status
- **Confidence-based Review**: Results organized by confidence score (0.8+, 0.6+, 0.4+)
- **Rule Editing**: In-place editing with diff highlighting
- **Batch Operations**: Copy, download individual rules or bulk export
- **Export Options**: Download as JSON or ZIP archives

### 🎨 Design System
- **IBM Plex Typography**: Modern, technical font family
- **Semantic Color Palette**: Black/white/grey base with semantic colors
- **OpenAI-inspired UI**: Clean, modern interface following OpenAI dev platform patterns
- **Responsive Layout**: Optimized for desktop and tablet use

## Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn
- Canonical backend server running on `localhost:8000`

### Installation

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Start the development server**:
   ```bash
   npm run dev
   ```

3. **Open your browser**:
   Navigate to [http://localhost:3000](http://localhost:3000)

### Backend Integration

The frontend is properly connected to the Canonical backend through a Next.js proxy configuration. The frontend automatically routes `/api/*` requests to the backend running on `localhost:8000`.

#### Quick Start

1. **Start the backend server:**
   ```bash
   cd ../  # Go to main canonical directory
   python3 -m src.canonical.cli serve --host 0.0.0.0 --port 8000
   ```

2. **Start the frontend development server:**
   ```bash
   cd frontend
   npm run dev
   ```

3. **Access the application:**
   - Open http://localhost:3000 in your browser
   - The frontend will automatically connect to the backend API

#### API Proxy Configuration

The `next.config.js` file contains the proxy configuration that routes frontend API calls to the backend:

```javascript
module.exports = {
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://localhost:8000/:path*',
      },
    ];
  },
};
```

This means:
- Frontend calls to `/api/convert` → Backend `http://localhost:8000/convert`
- Frontend calls to `/api/health` → Backend `http://localhost:8000/health`

#### Testing the Connection

You can verify the connection is working by:

1. **Health Check:** Visit http://localhost:3000/api/health
2. **Direct API Test:**
   ```bash
   curl -X POST "http://localhost:3000/api/convert" \
     -H "Content-Type: application/json" \
     -d '{
       "source_rule": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 4103\n  condition: selection",
       "source_format": "sigma", 
       "target_format": "kustoql"
     }'
   ```

#### No Mock API Required

The frontend now connects directly to the real Canonical backend. The previous `mock-api.py` has been removed as it's no longer needed.

## Development

### Project Structure
```
frontend/
├── src/
│   ├── app/                  # Next.js app router
│   │   ├── layout.tsx       # Root layout with React Query
│   │   ├── page.tsx         # Main page with tabs
│   │   └── globals.css      # Global styles and fonts
│   └── components/
│       ├── PlaygroundTab.tsx    # Single rule conversion
│       └── BulkUploadTab.tsx    # Bulk processing interface
├── public/                  # Static assets
├── tailwind.config.ts      # Tailwind configuration
├── next.config.js          # Next.js configuration
└── package.json
```

### Key Technologies
- **Next.js 14**: React framework with App Router
- **TypeScript**: Type safety and better development experience
- **Tailwind CSS**: Utility-first CSS framework
- **React Query**: Data fetching and state management
- **Headless UI**: Accessible UI components
- **Lucide React**: Modern icon library
- **React Dropzone**: File upload functionality

### Available Scripts
- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint

## API Integration

The frontend communicates with the Canonical backend through these endpoints:

### Conversion Endpoints
- `POST /convert` - Generic conversion endpoint
- `POST /convert/sigma/kustoql` - Sigma to KustoQL
- `POST /convert/qradar/kustoql` - QRadar to KustoQL
- `POST /convert/kibanaql/kustoql` - KibanaQL to KustoQL
- And more...

### Request Format
```typescript
{
  source_rule: string;
  source_format: "sigma" | "qradar" | "kibanaql";
  target_format: "kustoql" | "kibanaql" | "eql" | "qradar" | "spl" | "sigma";
  context?: Record<string, any>;
}
```

### Response Format
```typescript
{
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
```

## Customization

### Styling
The design system is configured in `tailwind.config.ts` with:
- IBM Plex Sans font family
- Custom color palette
- OpenAI-inspired component styling
- Semantic color naming

### Adding New Formats
To add support for new rule formats:

1. Update format lists in components:
   ```typescript
   const sourceFormats = [
     { value: 'new-format', label: 'New Format' },
     // ... existing formats
   ];
   ```

2. Add sample rules:
   ```typescript
   const sampleRules = {
     'new-format': `sample rule content...`,
     // ... existing samples
   };
   ```

3. Backend endpoints should be automatically supported through the generic `/convert` endpoint.

## Production Deployment

### Build for Production
```bash
npm run build
npm start
```

### Environment Variables
Create a `.env.local` file for environment-specific configuration:
```env
NEXT_PUBLIC_API_BASE_URL=https://your-backend-url.com
```

### Docker Deployment
Create a `Dockerfile` in the frontend directory:
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
```

## Contributing

1. Follow the existing code style and component patterns
2. Use TypeScript for all new components
3. Follow the IBM Plex typography system
4. Maintain the OpenAI-inspired design patterns
5. Test with multiple rule formats and edge cases

## License

This frontend application is part of the Canonical SIEM Rule Converter project and follows the same licensing terms as the main project.
