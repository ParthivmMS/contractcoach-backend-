from fastapi import FastAPI, File, UploadFile
import requests
import PyPDF2
import docx
import io

app = FastAPI()

# ✅ Load API key from environment variable (set in Render dashboard)
import os
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def extract_text(file: UploadFile) -> str:
    """Extract text from uploaded PDF or DOCX"""
    content = file.file.read()  # Read raw bytes
    text = ""

    if file.filename.endswith(".pdf"):
        reader = PyPDF2.PdfReader(io.BytesIO(content))
        for page in reader.pages:
            text += page.extract_text() or ""

    elif file.filename.endswith(".docx"):
        doc = docx.Document(io.BytesIO(content))
        for para in doc.paragraphs:
            text += para.text + "\n"

    else:
        raise ValueError("Unsupported file type. Only PDF and DOCX allowed.")

    return text.strip()

def summarize_text(text: str) -> str:
    """Send extracted text to OpenRouter and get summary"""
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "openai/gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a legal assistant that summarizes contracts."},
            {"role": "user", "content": f"Summarize this contract:\n{text}"}
        ]
    }

    response = requests.post(OPENROUTER_URL, headers=headers, json=payload)

    if response.status_code != 200:
        return f"Error: {response.text}"

    data = response.json()
    return data.get("choices", [{}])[0].get("message", {}).get("content", "Error: no summary")

@app.post("/summarize/")
async def summarize_contract(file: UploadFile = File(...)):
    try:
        text = extract_text(file)
        if not text:
            return {"summary": "Error: could not extract text"}
        summary = summarize_text(text)
        return {"summary": summary}
    except Exception as e:
        return {"summary": f"Failed to analyze file: {str(e)}"}
