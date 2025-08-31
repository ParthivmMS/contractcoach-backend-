const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const pdf = require('pdf-parse');
const mammoth = require('mammoth');

const app = express();
const PORT = process.env.PORT || 3000;

console.log('🚀 Starting ContractCoach Backend Server...');
console.log('Environment:', process.env.NODE_ENV || 'development');
console.log('OpenRouter API Key:', process.env.OPENROUTER_API_KEY ? 'SET ✅' : 'MISSING ❌');

// CORS Configuration - Allow your frontend domains
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://ai-contractcoach.vercel.app',
        'https://contractcoach.vercel.app', 
        'https://parthivmms.github.io',
        /\.vercel\.app$/,
        /\.github\.io$/,
        /localhost:\d+$/
    ],
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Configure multer for file uploads
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 30 * 1024 * 1024 }, // 30MB
    fileFilter: (req, file, cb) => {
        const allowed = ['application/pdf', 'application/msword', 
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 
                        'text/plain'];
        if (allowed.includes(file.mimetype) || file.originalname.toLowerCase().endsWith('.txt')) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF, DOC, DOCX, and TXT files allowed'));
        }
    }
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: '⚖️ ContractCoach Backend API',
        status: 'running',
        version: '1.0.0',
        endpoints: {
            health: 'GET /health',
            analyze: 'POST /api/analyze'
        },
        openRouterConnected: !!process.env.OPENROUTER_API_KEY
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        memory: process.memoryUsage(),
        openRouterConfigured: !!process.env.OPENROUTER_API_KEY
    });
});

// Main contract analysis endpoint
app.post('/api/analyze', upload.single('contract'), async (req, res) => {
    console.log('📋 Contract analysis request received');
    console.log('File:', req.file ? `${req.file.originalname} (${req.file.size} bytes)` : 'None');
    console.log('Text length:', req.body.text ? req.body.text.length : 0);
    
    try {
        let contractText = '';
        
        // Extract text from file or use provided text
        if (req.file) {
            contractText = await extractTextFromFile(req.file);
            console.log('📄 Extracted text length:', contractText.length);
        } else if (req.body.text) {
            contractText = req.body.text;
            console.log('📝 Using provided text');
        } else {
            return res.status(400).json({
                error: 'No contract provided',
                message: 'Please upload a file or provide contract text'
            });
        }

        if (!contractText || contractText.trim().length < 50) {
            return res.status(400).json({
                error: 'Contract text too short',
                message: 'Contract must contain at least 50 characters'
            });
        }

        console.log('🤖 Starting AI analysis...');
        const analysis = await analyzeWithOpenRouter(contractText);
        
        console.log('✅ Analysis completed successfully');
        
        res.json({
            success: true,
            analysis: analysis,
            metadata: {
                textLength: contractText.length,
                processedAt: new Date().toISOString(),
                source: req.file ? 'file' : 'text',
                model: 'meta-llama/llama-3.1-8b-instruct:free'
            }
        });

    } catch (error) {
        console.error('❌ Analysis error:', error.message);
        
        res.status(500).json({
            error: 'Analysis failed',
            message: error.message,
            fallback: 'Using keyword-based analysis'
        });
    }
});

// Extract text from uploaded files
async function extractTextFromFile(file) {
    const { buffer, mimetype, originalname } = file;
    
    try {
        if (mimetype === 'application/pdf') {
            const data = await pdf(buffer);
            return data.text;
        }
        
        if (mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
            const result = await mammoth.extractRawText({ buffer });
            return result.value;
        }
        
        if (mimetype === 'text/plain' || originalname.toLowerCase().endsWith('.txt')) {
            return buffer.toString('utf8');
        }
        
        // Fallback for DOC files
        if (mimetype === 'application/msword') {
            return buffer.toString('utf8');
        }
        
        throw new Error(`Unsupported file type: ${mimetype}`);
        
    } catch (error) {
        throw new Error(`Failed to extract text: ${error.message}`);
    }
}

// Analyze contract with OpenRouter
async function analyzeWithOpenRouter(contractText) {
    const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
    
    if (!OPENROUTER_API_KEY) {
        console.error('🔑 OpenRouter API key not found');
        return createFallbackAnalysis(contractText);
    }

    const prompt = `You are a legal contract expert. Analyze this contract and respond with ONLY valid JSON in this exact format:

{
  "summary": "Brief summary of the contract in 1-2 sentences",
  "overall_risk_score": 7,
  "overall_confidence": "High",
  "clauses": [
    {
      "clause_type": "Payment",
      "clause_text": "Brief excerpt of risky clause",
      "risk_level": "High",
      "risk_score": 85,
      "confidence": "High",
      "why_risky_plain": "Plain English explanation of why this is risky",
      "why_risky_legal": "Legal explanation in one line",
      "market_standard_alternative": "Suggested better clause language",
      "negotiation_script_friendly": "Friendly way to negotiate this",
      "negotiation_script_firm": "Firm way to negotiate this",
      "priority": "Urgent"
    }
  ],
  "top_actions": ["Action 1", "Action 2", "Action 3"],
  "disclaimer": "This is not legal advice. Consult a licensed attorney.",
  "assumptions": [],
  "meta": {
    "jurisdiction_flag": "US",
    "contract_type": "Service Agreement",
    "timestamp_utc": "${new Date().toISOString()}"
  }
}

Focus on: payment terms, termination clauses, IP ownership, liability, confidentiality.

Contract: ${contractText.substring(0, 3000)}`;

    try {
        console.log('🌐 Calling OpenRouter API...');
        const response = await axios.post(
            'https://openrouter.ai/api/v1/chat/completions',
            {
                model: 'meta-llama/llama-3.1-8b-instruct:free',
                messages: [
                    { role: 'system', content: 'You are a contract analysis expert. Respond only with valid JSON.' },
                    { role: 'user', content: prompt }
                ],
                temperature: 0.1,
                max_tokens: 2000
            },
            {
                headers: {
                    'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
                    'Content-Type': 'application/json',
                    'HTTP-Referer': 'https://contractcoach.com',
                    'X-Title': 'ContractCoach'
                },
                timeout: 30000
            }
        );

        const aiResponse = response.data.choices[0].message.content.trim();
        console.log('🤖 OpenRouter response length:', aiResponse.length);
        
        // Clean the response (remove any markdown formatting)
        let cleanResponse = aiResponse;
        if (cleanResponse.startsWith('```json')) {
            cleanResponse = cleanResponse.replace(/```json\n?/, '').replace(/```$/, '');
        }
        
        const analysis = JSON.parse(cleanResponse);
        
        // Validate required fields
        if (!analysis.summary || !analysis.overall_risk_score) {
            throw new Error('Invalid AI response structure');
        }
        
        console.log('✅ AI analysis parsed successfully');
        return analysis;
        
    } catch (error) {
        console.error('🔴 OpenRouter error:', error.message);
        console.log('📋 Falling back to keyword analysis');
        return createFallbackAnalysis(contractText);
    }
}

// Fallback analysis when AI fails
function createFallbackAnalysis(contractText) {
    console.log('🔄 Creating fallback keyword-based analysis');
    
    const text = contractText.toLowerCase();
    let riskScore = 5;
    const foundIssues = [];
    
    // Payment terms analysis
    if (text.includes('7 days') || text.includes('seven days')) {
        riskScore += 2;
        foundIssues.push({
            clause_type: 'Payment',
            clause_text: 'Short payment period detected',
            risk_level: 'High',
            risk_score: 90,
            confidence: 'High',
            why_risky_plain: 'A 7-day cure period is extremely short for most businesses',
            why_risky_legal: 'Insufficient time for payment processing and dispute resolution',
            market_standard_alternative: 'Change cure period to 30 days with written notice',
            negotiation_script_friendly: 'We typically work on 30-day terms. Could we adjust this?',
            negotiation_script_firm: 'We require a 30-day cure period for payment issues',
            priority: 'Urgent'
        });
    }
    
    // Termination analysis
    if (text.includes('immediate') && text.includes('terminat')) {
        riskScore += 1;
        foundIssues.push({
            clause_type: 'Termination',
            clause_text: 'Immediate termination clause found',
            risk_level: 'High',
            risk_score: 85,
            confidence: 'Medium',
            why_risky_plain: 'Immediate termination gives the other party too much power',
            why_risky_legal: 'No cure period for potential breaches',
            market_standard_alternative: 'Add 30-day written notice requirement',
            negotiation_script_friendly: 'Could we add a notice period before termination?',
            negotiation_script_firm: 'We need written notice before any termination',
            priority: 'Important'
        });
    }
    
    // Indemnification analysis
    if (text.includes('indemnif') && (text.includes('all') || text.includes('any'))) {
        riskScore += 1;
        foundIssues.push({
            clause_type: 'Liability',
            clause_text: 'Broad indemnification clause detected',
            risk_level: 'Medium',
            risk_score: 70,
            confidence: 'Medium',
            why_risky_plain: 'You may be responsible for costs even if not at fault',
            why_risky_legal: 'Unlimited indemnification exposure',
            market_standard_alternative: 'Limit indemnification to specific breaches only',
            negotiation_script_friendly: 'Can we limit this to cases where we are actually at fault?',
            negotiation_script_firm: 'Indemnification should be limited to our direct breaches',
            priority: 'Important'
        });
    }

    return {
        summary: `Keyword-based analysis found ${foundIssues.length} potential risk areas in this contract.`,
        overall_risk_score: Math.min(riskScore, 10),
        overall_confidence: 'Medium',
        clauses: foundIssues.length > 0 ? foundIssues : [{
            clause_type: 'General',
            clause_text: 'Contract reviewed',
            risk_level: 'Low',
            risk_score: 50,
            confidence: 'Low',
            why_risky_plain: 'No major risks detected in keyword analysis',
            why_risky_legal: 'Standard contract terms appear present',
            market_standard_alternative: 'Consider full legal review for comprehensive analysis',
            negotiation_script_friendly: 'The contract looks fairly standard',
            negotiation_script_firm: 'We find the terms acceptable as written',
            priority: 'Optional'
        }],
        top_actions: [
            foundIssues.length > 0 ? 'Address high-priority clauses first' : 'Review contract with legal counsel',
            'Negotiate payment terms if applicable',
            'Clarify termination procedures',
            'Review liability and indemnification',
            'Document any agreed changes in writing'
        ],
        disclaimer: 'This analysis is not legal advice. Consult a licensed attorney for binding legal advice.',
        assumptions: ['Analysis based on keyword detection', 'AI analysis unavailable'],
        meta: {
            jurisdiction_flag: 'US',
            contract_type: 'General',
            timestamp_utc: new Date().toISOString()
        }
    };
}

// Error handling
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.message);
    
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
            error: 'File too large',
            message: 'Please upload files under 30MB'
        });
    }
    
    res.status(500).json({
        error: 'Internal server error',
        message: 'Something went wrong'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Not found',
        message: `${req.method} ${req.originalUrl} not found`,
        endpoints: ['GET /', 'GET /health', 'POST /api/analyze']
    });
});

app.listen(PORT, () => {
    console.log('✅ ContractCoach Backend Started Successfully!');
    console.log(`🌐 Server running on port ${PORT}`);
    console.log(`🔗 Health: https://contractcoach-backend.onrender.com/health`);
    console.log(`📋 API: https://contractcoach-backend.onrender.com/api/analyze`);
    console.log('🚀 Ready for contract analysis!');
});
