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
    allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'Accept']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Configure multer for file uploads
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 30 * 1024 * 1024 }, // 30MB
    fileFilter: (req, file, cb) => {
        const allowed = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain'
        ];
        if (allowed.includes(file.mimetype) || file.originalname.toLowerCase().endsWith('.txt') || file.originalname.toLowerCase().endsWith('.doc')) {
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
    console.log('Text length (body):', req.body.text ? req.body.text.length : 0);
    console.log('Requester IP:', req.ip, 'User-Agent:', req.get('User-Agent'));

    try {
        let contractText = '';

        // Extract text from file or use provided text
        if (req.file) {
            contractText = await extractTextFromFile(req.file);
            console.log('📄 Extracted text length:', contractText.length);
        } else if (req.body.text) {
            contractText = String(req.body.text);
            console.log('📝 Using provided text');
        } else {
            return res.status(400).json({
                error: 'No contract provided',
                message: 'Please upload a file or provide contract text'
            });
        }

        // FIX: sanitize and set upper limit for what we send to the model
        contractText = contractText.replace(/\u00A0/g, ' ').trim(); // replace non-breaking spaces
        const MIN_LENGTH = 50;
        if (!contractText || contractText.length < MIN_LENGTH) {
            return res.status(400).json({
                error: 'Contract text too short',
                message: `Contract must contain at least ${MIN_LENGTH} characters`
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
                model: 'meta-llama/llama-3.1-8b-instruct:free' // FIX: keep consistent with prompt
            }
        });

    } catch (error) {
        // FIX: log full error stack for debugging, but return sanitized message to client
        console.error('❌ Analysis error:', error.stack || error.message || error);
        res.status(500).json({
            error: 'Analysis failed',
            message: error.message || 'Internal server error',
            fallback: 'Using keyword-based analysis'
        });
    }
});

// Extract text from uploaded files
async function extractTextFromFile(file) {
    const { buffer, mimetype, originalname } = file;

    try {
        // PDF handling
        if (mimetype === 'application/pdf' || originalname.toLowerCase().endsWith('.pdf')) {
            // FIX: pdf-parse expects a Buffer — already provided
            const data = await pdf(buffer);
            const text = (data && data.text) ? String(data.text) : '';
            // FIX: detect scanned PDFs (no extracted text)
            if (!text || text.trim().length < 40) {
                // give clearer guidance instead of silently failing
                throw new Error('Scanned or image-based PDF detected (no extractable text). OCR required.');
            }
            return text;
        }

        // DOCX handling
        if (mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' || originalname.toLowerCase().endsWith('.docx')) {
            const result = await mammoth.extractRawText({ buffer });
            return result && result.value ? String(result.value) : '';
        }

        // Plain text
        if (mimetype === 'text/plain' || originalname.toLowerCase().endsWith('.txt')) {
            return buffer.toString('utf8');
        }

        // DOC (older Word) fallback — best-effort
        if (mimetype === 'application/msword' || originalname.toLowerCase().endsWith('.doc')) {
            // FIX: mammoth cannot handle binary .doc — try best-effort fallback to utf8 text
            const asText = buffer.toString('utf8');
            if (asText && asText.trim().length > 40) {
                return asText;
            } else {
                throw new Error('DOC file detected but could not reliably extract text. Consider saving as DOCX or PDF.');
            }
        }

        throw new Error(`Unsupported file type: ${mimetype || originalname}`);
    } catch (error) {
        // propagate a clearer error up to the caller
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

    // FIX: limit how much of contract we put into the prompt (models have token limits)
    // Keep first N characters (safe) and mention if truncated
    const MAX_CHARS_FOR_PROMPT = 16000; // reasonable limit; adjust by model token size
    let truncatedNotice = '';
    let promptContract = contractText;
    if (contractText.length > MAX_CHARS_FOR_PROMPT) {
        truncatedNotice = `\n\n[NOTE: Contract truncated to ${MAX_CHARS_FOR_PROMPT} characters for analysis; full document not processed.]`;
        promptContract = contractText.substring(0, MAX_CHARS_FOR_PROMPT);
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

Contract: ${promptContract}${truncatedNotice}`;

    // FIX: Add a simple retry mechanism for transient errors (once)
    const MAX_ATTEMPTS = 2;
    let attempt = 0;
    let lastError = null;
    while (attempt < MAX_ATTEMPTS) {
        attempt++;
        try {
            console.log(`🌐 Calling OpenRouter API... attempt ${attempt}`);
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

            // FIX: Be defensive about response shapes (OpenRouter/other proxies may vary)
            let aiContent = '';
            try {
                if (response.data) {
                    // Common shape: response.data.choices[0].message.content
                    if (Array.isArray(response.data.choices) && response.data.choices[0]) {
                        aiContent = (response.data.choices[0].message && response.data.choices[0].message.content) ||
                                    response.data.choices[0].text || '';
                    } else if (response.data.output) {
                        // some routers wrap output
                        aiContent = JSON.stringify(response.data.output);
                    } else if (typeof response.data === 'string') {
                        aiContent = response.data;
                    } else {
                        aiContent = JSON.stringify(response.data);
                    }
                } else {
                    throw new Error('Empty response from OpenRouter');
                }
            } catch (parseErr) {
                console.warn('⚠️ Unexpected response shape — falling back to raw response stringify');
                aiContent = JSON.stringify(response.data);
            }

            // Trim and log a truncated preview for debugging
            const preview = aiContent.length > 2000 ? aiContent.substring(0, 2000) + '...[truncated]' : aiContent;
            console.log('🤖 OpenRouter raw response preview:', preview);

            // FIX: remove common code fences and markdown fences
            let cleanResponse = aiContent.trim();
            if (cleanResponse.startsWith('```')) {
                // remove starting ```json or ```
                cleanResponse = cleanResponse.replace(/^```(?:json)?\s*/, '').replace(/\s*```$/, '');
            }

            // FIX: Some models output explanatory preface — try to extract first JSON block
            let parsed = null;
            try {
                // Try direct JSON parse first
                parsed = JSON.parse(cleanResponse);
            } catch (e) {
                // Attempt to extract JSON substring using regex
                const jsonMatch = cleanResponse.match(/\{[\s\S]*\}\s*$/);
                if (jsonMatch) {
                    try {
                        parsed = JSON.parse(jsonMatch[0]);
                    } catch (e2) {
                        // try more permissive: find first { and last }
                        const firstIndex = cleanResponse.indexOf('{');
                        const lastIndex = cleanResponse.lastIndexOf('}');
                        if (firstIndex !== -1 && lastIndex !== -1 && lastIndex > firstIndex) {
                            const candidate = cleanResponse.substring(firstIndex, lastIndex + 1);
                            parsed = JSON.parse(candidate);
                        } else {
                            throw new Error('Could not parse JSON from AI response');
                        }
                    }
                } else {
                    throw new Error('No JSON object found in AI response');
                }
            }

            // Validate required fields
            if (!parsed || !parsed.summary || typeof parsed.overall_risk_score === 'undefined') {
                throw new Error('Invalid AI response structure (missing required keys)');
            }

            // Return parsed analysis + raw model output for debugging
            return Object.assign({}, parsed, { raw_model_output: aiContent });

        } catch (error) {
            lastError = error;
            const status = error.response && error.response.status;
            console.error(`🔴 OpenRouter attempt ${attempt} failed:`, (error.message || error) + (status ? ` (status ${status})` : ''));
            // if client or parse error, don't retry; if transient (5xx or 429), retry once
            if (attempt >= MAX_ATTEMPTS || (status && status < 500 && status !== 429)) {
                break;
            }
            console.log('⏳ Retrying OpenRouter call...');
            await sleep(1000 * attempt); // backoff
        }
    }

    // FIX: On total failure, log last error and fallback to keyword analysis
    console.error('🔴 OpenRouter final error:', lastError && (lastError.stack || lastError.message || lastError));
    console.log('📋 Falling back to keyword analysis');
    // Optionally include lastError.message inside assumptions for debugging
    const fallback = createFallbackAnalysis(contractText);
    // attach debug note
    fallback.assumptions = fallback.assumptions || [];
    fallback.assumptions.push(`AI_failed: ${lastError ? (lastError.message || String(lastError)) : 'unknown'}`);
    return fallback;
}

// small helper
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Fallback analysis when AI fails
function createFallbackAnalysis(contractText) {
    console.log('🔄 Creating fallback keyword-based analysis');

    const text = String(contractText).toLowerCase();
    let riskScore = 5;
    const foundIssues = [];

    // Payment terms analysis
    if (text.includes('7 days') || text.includes('seven days') || text.includes('due within 7')) {
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
    if (text.includes('indemnif') && (text.includes('all') || text.includes('any') || text.includes('loss') || text.includes('liabil'))) {
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
    console.error('Unhandled error:', err.stack || err.message || err);

    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
            error: 'File too large',
            message: 'Please upload files under 30MB'
        });
    }

    // Provide helpful but non-sensitive error to client
    res.status(500).json({
        error: 'Internal server error',
        message: 'Something went wrong while processing your request'
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
