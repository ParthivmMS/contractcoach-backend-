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
    // FIX: allow common headers used by fetch/XHR
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
        if (allowed.includes(file.mimetype) ||
            file.originalname.toLowerCase().endsWith('.txt') ||
            file.originalname.toLowerCase().endsWith('.doc')) {
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

        // FIX: sanitize and set minimum length
        contractText = contractText.replace(/\u00A0/g, ' ').trim();
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

        // Ensure consistent response shape (FIX)
        const normalized = ensureAnalysisShape(analysis);

        res.json({
            success: true,
            analysis: normalized,
            metadata: {
                textLength: contractText.length,
                processedAt: new Date().toISOString(),
                source: req.file ? 'file' : 'text',
                model: 'meta-llama/llama-3.1-8b-instruct'
            }
        });

    } catch (error) {
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
            const data = await pdf(buffer);
            const text = (data && data.text) ? String(data.text) : '';
            // FIX: detect scanned PDFs (no extracted text)
            if (!text || text.trim().length < 40) {
                // Provide clear guidance for OCR
                throw new Error('Scanned or image-based PDF detected (no extractable text). OCR required.');
            }
            return text;
        }

        // DOCX handling
        if (mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
            originalname.toLowerCase().endsWith('.docx')) {
            const result = await mammoth.extractRawText({ buffer });
            return result && result.value ? String(result.value) : '';
        }

        // Plain text
        if (mimetype === 'text/plain' || originalname.toLowerCase().endsWith('.txt')) {
            return buffer.toString('utf8');
        }

        // DOC (older Word) fallback — best-effort
        if (mimetype === 'application/msword' || originalname.toLowerCase().endsWith('.doc')) {
            const asText = buffer.toString('utf8');
            if (asText && asText.trim().length > 40) {
                return asText;
            } else {
                throw new Error('DOC file detected but could not reliably extract text. Consider saving as DOCX or PDF.');
            }
        }

        throw new Error(`Unsupported file type: ${mimetype || originalname}`);
    } catch (error) {
        throw new Error(`Failed to extract text: ${error.message}`);
    }
}

// Analyze contract with OpenRouter
async function analyzeWithOpenRouter(contractText) {
    const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;

    if (!OPENROUTER_API_KEY) {
        console.error('🔑 OpenRouter API key not found');
        // Attach assumption to fallback for debugging
        const fallback = createFallbackAnalysis(contractText);
        fallback.assumptions = (fallback.assumptions || []).concat(['AI_unavailable: OPENROUTER_API_KEY missing']);
        return fallback;
    }

    // FIX: limit prompt size and add truncated notice
    const MAX_CHARS_FOR_PROMPT = 16000;
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

    // FIX: retry once on transient errors
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
                    model: 'meta-llama/llama-3.1-8b-instruct',
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

            // FIX: tolerate multiple response shapes
            let aiContent = '';
            if (response && response.data) {
                if (Array.isArray(response.data.choices) && response.data.choices[0]) {
                    aiContent = (response.data.choices[0].message && response.data.choices[0].message.content) ||
                                response.data.choices[0].text || '';
                } else if (response.data.output) {
                    aiContent = JSON.stringify(response.data.output);
                } else if (typeof response.data === 'string') {
                    aiContent = response.data;
                } else {
                    aiContent = JSON.stringify(response.data);
                }
            } else {
                throw new Error('Empty response from OpenRouter');
            }

            const preview = aiContent.length > 1500 ? aiContent.substring(0, 1500) + '...[truncated]' : aiContent;
            console.log('🤖 OpenRouter raw response preview:', preview);

            // FIX: strip code fences and attempt to parse JSON robustly
            let cleanResponse = aiContent.trim();
            if (cleanResponse.startsWith('```')) {
                cleanResponse = cleanResponse.replace(/^```(?:json)?\s*/, '').replace(/\s*```$/, '');
            }

            // Attempt direct JSON parse
            let parsed = null;
            try {
                parsed = JSON.parse(cleanResponse);
            } catch (e) {
                // Try to extract JSON block
                const jsonMatch = cleanResponse.match(/\{[\s\S]*\}\s*$/);
                if (jsonMatch) {
                    try {
                        parsed = JSON.parse(jsonMatch[0]);
                    } catch (e2) {
                        // Try find first { and last } and parse
                        const first = cleanResponse.indexOf('{');
                        const last = cleanResponse.lastIndexOf('}');
                        if (first !== -1 && last !== -1 && last > first) {
                            const candidate = cleanResponse.substring(first, last + 1);
                            parsed = JSON.parse(candidate);
                        } else {
                            throw new Error('Could not extract JSON from AI response');
                        }
                    }
                } else {
                    throw new Error('No JSON found in AI response');
                }
            }

            // Validate minimal required keys
            if (!parsed || !parsed.summary || typeof parsed.overall_risk_score === 'undefined') {
                throw new Error('Invalid AI response structure (missing summary or overall_risk_score)');
            }

            // Attach raw output for debugging
            parsed.raw_model_output = aiContent;

            return parsed;

        } catch (error) {
            lastError = error;
            const status = error.response && error.response.status;
            console.error(`🔴 OpenRouter attempt ${attempt} failed:`, (error.message || error) + (status ? ` (status ${status})` : ''));
            // retry only on server errors or rate limit
            if (attempt >= MAX_ATTEMPTS || (status && status < 500 && status !== 429)) {
                break;
            }
            console.log('⏳ Retrying OpenRouter call in 1s...');
            await sleep(1000 * attempt);
        }
    }

    // On failure, fallback
    console.error('🔴 OpenRouter final error:', lastError && (lastError.stack || lastError.message || lastError));
    console.log('📋 Falling back to keyword analysis');
    const fallback = createFallbackAnalysis(contractText);
    fallback.assumptions = (fallback.assumptions || []).concat([`AI_failed: ${lastError ? (lastError.message || String(lastError)) : 'unknown'}`]);
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

    // Indemnification / Liability analysis
    if (text.includes('indemnif') || text.includes('indemnity') || (text.includes('liabil') && text.includes('limit'))) {
        riskScore += 1;
        foundIssues.push({
            clause_type: 'Liability/Indemnity',
            clause_text: 'Broad indemnity or unlimited liability language detected',
            risk_level: 'Medium',
            risk_score: 70,
            confidence: 'Medium',
            why_risky_plain: 'Potential for broad financial exposure in indemnity or unlimited liability',
            why_risky_legal: 'Creates open-ended indemnification obligations without caps or limitations',
            market_standard_alternative: 'Limit indemnity to direct damages and breaches and consider caps',
            negotiation_script_friendly: 'Can we limit indemnity to direct breaches and set reasonable caps?',
            negotiation_script_firm: 'Indemnity must be limited to our direct breaches with monetary caps',
            priority: 'Important'
        });
    }

     // Governing law / jurisdiction
    if (text.includes('governed by') || text.includes('governing law') || text.includes('jurisdiction')) {
        foundIssues.push({
            clause_type: 'Governing Law',
            clause_text: 'Governing law/jurisdiction clause present',
            risk_level: 'Low',
            risk_score: 45,
            confidence: 'Medium',
            why_risky_plain: 'Choice of law affects enforceability and dispute costs',
            why_risky_legal: 'Consider whether forum selection or arbitration is appropriate',
            market_standard_alternative: 'Consider mutual jurisdiction or neutral arbitration if needed',
            negotiation_script_friendly: 'Can we consider a neutral jurisdiction or arbitration?',
            negotiation_script_firm: 'We request disputes be resolved under our local jurisdiction or via arbitration.',
            priority: 'Optional'
        });
    }

    // If none found, add a default low-risk note
    const clauses = foundIssues.length > 0 ? foundIssues : [{
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
    }];

    // Compute overall score (FIX: ensure numeric and between 1-10)
    const totalRisk = Math.min(10, Math.max(1, 5 + (foundIssues.length ? foundIssues.length - 1 : 0)));

    return {
        summary: `Keyword-based analysis found ${foundIssues.length} potential risk areas in this contract.`,
        overall_risk_score: totalRisk,
        overall_confidence: 'Medium',
        clauses: clauses,
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

// Ensure consistent analysis shape (adds defaults if missing) - FIX
function ensureAnalysisShape(a) {
    const out = Object.assign({}, a);
    out.summary = out.summary || 'No summary available';
    out.overall_risk_score = (typeof out.overall_risk_score !== 'undefined') ? out.overall_risk_score : 5;
    out.overall_confidence = out.overall_confidence || 'Medium';
    out.clauses = Array.isArray(out.clauses) ? out.clauses : (out.clause ? [out.clause] : []);
    if (out.clauses.length === 0) {
        out.clauses = [{
            clause_type: 'General',
            clause_text: 'No specific clauses detected',
            risk_level: 'Low',
            risk_score: 50,
            confidence: 'Low',
            why_risky_plain: 'No major issues detected',
            priority: 'Optional'
        }];
    }
    out.top_actions = Array.isArray(out.top_actions) ? out.top_actions : ['Review contract'];
    out.disclaimer = out.disclaimer || 'This analysis is not legal advice. Consult a licensed attorney.';
    out.assumptions = Array.isArray(out.assumptions) ? out.assumptions : (out.assumptions ? [out.assumptions] : []);
    out.meta = out.meta || { jurisdiction_flag: 'US', contract_type: 'General', timestamp_utc: new Date().toISOString() };
    return out;
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
