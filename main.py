from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from PyPDF2 import PdfReader
import docx
import openai  # For OpenRouter, we still use `openai.ChatCompletion` style
import os
import requests

app = FastAPI()

# ===== CORS for frontend =====
origins = ["*"]  # Adjust to your frontend domain in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== OpenRouter API Key =====
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")  # or directly: "your_key_here"
MODEL_NAME = "mistral"  # You can also choose other OpenRouter models

# ===== Utility: Read file content =====
def extract_text(file: UploadFile):
    filename = file.filename.lower()
    if filename.endswith(".pdf"):
        reader = PdfReader(file.file)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return text
    elif filename.endswith(".docx"):
        doc = docx.Document(file.file)
        text = "\n".join([para.text for para in doc.paragraphs])
        return text
    elif filename.endswith(".txt"):
        return file.file.read().decode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="Unsupported file type")

# ===== OpenRouter summary =====
def get_summary_openrouter(prompt):
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500
    }

    response = requests.post(url, json=payload)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error calling OpenRouter API")
    
    data = response.json()
    # OpenRouter usually returns summary in 'result' or 'completion'
    if "result" in data:
        return data["result"]
    elif "completion" in data:
        return data["completion"]
    else:
        # Fallback: print full response for debugging
        print("OpenRouter response:", data)
        return "No summary returned from OpenRouter"

# ===== API Endpoint =====
@app.post("/")
async def summarize_file(file: UploadFile = File(...)):
    try:
        text = extract_text(file)
        if not text.strip():
            return {"summary": "The file is empty or could not extract text."}
        
        summary = get_summary_openrouter(text)
        return {"summary": summary}
    except Exception as e:
        print("Error:", str(e))
        raise HTTPException(status_code=500, detail=str(e))
