const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const pdf = require('pdf-parse');
const mammoth = require('mammoth');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://ai-contractcoach.vercel.app/',
        'ai-contractcoach-parthiv-m-ss-projects.vercel.app',
        // Add your actual Vercel domain here
    ],
    credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 30 * 1024 * 1024 // 30MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain'
        ];
        
        if (allowedTypes.includes(file.mimetype) || file.originalname.toLowerCase().endsWith('.txt')) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only PDF, DOC, DOCX, and TXT files are allowed.'));
        }
    }
});

// Health check endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'ContractCoach Backend API is running! 🚀',
        version: '1.0.0',
        endpoints: {
            analyze: 'POST /api/analyze',
            health: 'GET /health'
        }
    });
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Contract analysis endpoint
app.post('/api/analyze', upload.single('contract'), async (req, res) => {
    console.log('📄 Contract analysis request received');
    
    try {
        let contractText = '';
        
        // Handle file upload
        if (req.file) {
            console.log(`📎 Processing file: ${req.file.originalname} (${req.file.size} bytes)`);
            contractText = await extractTextFromFile(req.file);
        }
        // Handle pasted text
        else if (req.body.text) {
            console.log('📝 Processing pasted text');
            contractText = req.body.text;
        }
        else {
            return res.status(400).json({
                error: 'No contract provided',
                message: 'Please upload a file or provide contract text'
            });
        }

        if (!contractText || contractText.trim().length < 50) {
            return res.status(400).json({
                error: 'Contract text too short',
                message: 'Please provide at least 50 characters of contract text'
            });
        }

        console.log(`🔍 Analyzing contract (${contractText.length} characters)`);
        
        // Analyze with AI
        const analysis = await analyzeContractWithAI(contractText);
        
        console.log('✅ Analysis completed successfully');
        
        res.json({
            success: true,
            analysis: analysis,
            metadata: {
                textLength: contractText.length,
                processedAt: new Date().toISOString(),
                source: req.file ? 'file' : 'text'
            }
        });

    } catch (error) {
        console.error('❌ Analysis error:', error);
        
        res.status(500).json({
            error: 'Analysis failed',
            message: error.message,
            details: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Extract text from uploaded files
async function extractTextFromFile(file) {
    const { buffer, mimetype, originalname } = file;
    
    try {
        if (mimetype === 'application/pdf') {
            console.log('📄 Extracting text from PDF');
            const data = await pdf(buffer);
            return data.text;
        }
        
        if (mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
            console.log('📄 Extracting text from DOCX');
            const result = await mammoth.extractRawText({ buffer: buffer });
            return result.value;
        }
        
        if (mimetype === 'application/msword') {
            console.log('📄 Extracting text from DOC');
            // For .doc files, we'll treat as text (limited support)
            return buffer.toString('utf8');
        }
        
        if (mimetype === 'text/plain' || originalname.toLowerCase().endsWith('.txt')) {
            console.log('📄 Extracting text from TXT');
            return buffer.toString('utf8');
        }
        
        throw new Error(`Unsupported file type: ${mimetype}`);
        
    } catch (error) {
        console.error('File extraction error:', error);
        throw new Error(`Failed to extract text from file: ${error.message}`);
    }
}

// Analyze contract with OpenRouter API
async function analyzeContractWithAI(contractText) {
    console.log('🤖 Starting AI analysis...');
    
    const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
    
    if (!OPENROUTER_API_KEY) {
        throw new Error('OPENROUTER_API_KEY not configured in environment variables');
    }

    const prompt = `You are ContractCoach AI, a legal expert that analyzes contracts and identifies risks for small businesses. Analyze this contract and return a JSON response with the following structure:

{
  "summary": "Brief 1-2 sentence summary of the contract",
  "overall_risk_score": number (1-10, where 10 is highest risk),
  "overall_confidence": "Low|Medium|High",
  "clauses": [
    {
      "clause_type": "Payment|Termination|IP|Liability|Confidentiality|Other",
      "clause_text": "excerpt of the risky clause (max 150 characters)",
      "risk_level": "High|Medium|Low",
      "risk_score": number (0-100),
      "confidence": "Low|Medium|High",
      "why_risky_plain": "explanation in plain English (max 200 characters)",
      "why_risky_legal": "one-line legal explanation (max 100 characters)",
      "market_standard_alternative": "suggested alternative clause text",
      "negotiation_script_friendly": "friendly negotiation approach",
      "negotiation_script_firm": "firm negotiation approach",
      "priority": "Urgent|Important|Optional"
    }
  ],
  "top_actions": ["action1", "action2", "action3", "action4", "action5"],
  "disclaimer": "This analysis is not legal advice. Consult a licensed attorney for binding legal advice.",
  "assumptions": ["assumption1 if any", "assumption2 if any"],
  "meta": {
    "jurisdiction_flag": "US|UK|EU|Other|Unknown",
    "contract_type": "Service Agreement|NDA|Employment|Other",
    "timestamp_utc": "${new Date().toISOString()}"
  }
}

Focus on identifying:
1. Payment terms that are too short or unfavorable
2. Termination clauses that give one party too much power
3. IP ownership issues
4. Liability and indemnification problems
5. Confidentiality overreach
6. Governing law and jurisdiction issues

Contract text to analyze:
${contractText}

Return only valid JSON, no other text.`;

    try {
        const response = await axios.post(
            'https://openrouter.ai/api/v1/chat/completions',
            {
                model: 'meta-llama/llama-3.1-8b-instruct:free', // Free model
                messages: [
                    {
                        role: 'system',
                        content: 'You are a legal contract analysis expert. Always respond with valid JSON only.'
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                temperature: 0.1,
                max_tokens: 4000
            },
            {
                headers: {
                    'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
                    'Content-Type': 'application/json',
                    'HTTP-Referer': 'https://contractcoach.com',
                    'X-Title': 'ContractCoach'
                }
            }
        );

        const aiResponse = response.data.choices[0].message.content.trim();
        console.log('🤖 AI response received:', aiResponse.substring(0, 100) + '...');
        
        try {
            const analysis = JSON.parse(aiResponse);
            
            // Validate the response structure
            if (!analysis.summary || !analysis.overall_risk_score) {
                throw new Error('Invalid AI response structure');
            }
            
            return analysis;
            
        } catch (parseError) {
            console.error('JSON parse error:', parseError);
            console.log('Raw AI response:', aiResponse);
            
            // Fallback analysis if AI doesn't return valid JSON
            return createFallbackAnalysis(contractText);
        }

    } catch (error) {
        console.error('OpenRouter API error:', error.response?.data || error.message);
        
        // Return fallback analysis instead of failing completely
        return createFallbackAnalysis(contractText);
    }
}

// Fallback analysis when AI fails
function createFallbackAnalysis(contractText) {
    console.log('🔄 Creating fallback analysis');
    
    // Simple keyword-based risk detection
    const text = contractText.toLowerCase();
    let riskScore = 5; // Default medium risk
    const foundIssues = [];
    
    // Check for common risky patterns
    if (text.includes('7 days') || text.includes('seven days')) {
        riskScore += 2;
        foundIssues.push({
            clause_type: 'Payment',
            risk_level: 'High',
            why_risky_plain: 'Short payment cure period detected (7 days)',
            market_standard_alternative: 'Change to 30-day cure period',
            negotiation_script_friendly: 'Can we extend the payment cure period to 30 days?',
            priority: 'Urgent'
        });
    }
    
    if (text.includes('immediate') && text.includes('terminat')) {
        riskScore += 1;
        foundIssues.push({
            clause_type: 'Termination',
            risk_level: 'High',
            why_risky_plain: 'Immediate termination clause detected',
            market_standard_alternative: 'Add written notice requirement before termination',
            negotiation_script_friendly: 'Can we add a written notice period before termination?',
            priority: 'Important'
        });
    }
    
    if (text.includes('indemnif') && text.includes('regardless')) {
        riskScore += 1;
        foundIssues.push({
            clause_type: 'Liability',
            risk_level: 'Medium',
            why_risky_plain: 'Broad indemnification clause detected',
            market_standard_alternative: 'Limit indemnification to specific breaches',
            negotiation_script_friendly: 'Can we limit the indemnification scope?',
            priority: 'Important'
        });
    }

    return {
        summary: `Contract analysis completed using keyword detection. ${foundIssues.length} potential issues identified.`,
        overall_risk_score: Math.min(riskScore, 10),
        overall_confidence: 'Medium',
        clauses: foundIssues,
        top_actions: [
            'Review payment and termination terms',
            'Clarify liability and indemnification clauses',
            'Consider legal consultation for complex terms',
            'Negotiate more balanced terms',
            'Document any agreed changes in writing'
        ],
        disclaimer: 'This analysis is not legal advice. Consult a licensed attorney for binding legal advice.',
        assumptions: ['Analysis based on keyword detection', 'AI analysis temporarily unavailable'],
        meta: {
            jurisdiction_flag: 'Unknown',
            contract_type: 'Other',
            timestamp_utc: new Date().toISOString()
        }
    };
}

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                error: 'File too large',
                message: 'Please upload files smaller than 30MB'
            });
        }
    }
    
    res.status(500).json({
        error: 'Internal server error',
        message: 'Something went wrong processing your request'
    });
});

// Handle 404
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        message: `${req.method} ${req.originalUrl} is not a valid endpoint`,
        availableEndpoints: [
            'GET /',
            'GET /health',
            'POST /api/analyze'
        ]
    });
});

app.listen(PORT, () => {
    console.log('🚀 ContractCoach Backend Server Started');
    console.log(`📍 Server running on port ${PORT}`);
    console.log(`🌐 Health check: http://localhost:${PORT}/health`);
    console.log(`🔍 API endpoint: http://localhost:${PORT}/api/analyze`);
    console.log(`🔑 OpenRouter API Key: ${process.env.OPENROUTER_API_KEY ? 'Configured ✅' : 'Missing ❌'}`);
    console.log('Ready to analyze contracts! 📄⚖️');
});
