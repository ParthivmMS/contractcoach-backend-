from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import openai
import tempfile

# --- Initialize app ---
app = FastAPI(title="ContractCoach Backend")

# --- CORS settings ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For testing. Later, replace "*" with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- API Key from environment variable ---
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    raise ValueError("OPENROUTER_API_KEY is missing in environment variables")

openai.api_key = OPENROUTER_API_KEY

# --- Endpoint to check health ---
@app.get("/")
async def root():
    return {"message": "ContractCoach backend is running"}

# --- Endpoint to analyze uploaded file ---
@app.post("/analyze")
async def analyze_contract(file: UploadFile = File(...)):
    # Limit file types
    if file.content_type not in ["application/pdf", "application/msword", 
                                 "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                 "text/plain"]:
        raise HTTPException(status_code=400, detail="Invalid file type")

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=file.filename) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    # Read content as text (basic; for PDF/DOCX you may need libraries like pdfplumber or docx)
    text_content = content.decode("utf-8", errors="ignore")  # fallback for TXT

    # --- Call OpenRouter (Mistral or GPT) ---
    try:
        response = openai.chat.completions.create(
            model="mistral-7b-instruct",   # or another OpenRouter model
            messages=[
                {"role": "system", "content": "You are an AI legal assistant that summarizes contracts."},
                {"role": "user", "content": f"Summarize this contract and highlight risks:\n{text_content}"}
            ],
            temperature=0.2,
            max_tokens=1000
        )
        summary = response.choices[0].message["content"]

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI API error: {e}")

    return {"summary": summary}
