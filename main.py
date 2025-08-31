from fastapi import FastAPI, File, UploadFile
import requests
import PyPDF2
import docx
import os

app = FastAPI()

# Load API key from environment (Render Dashboard > Environment Variables)
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

@app.get("/")
def root():
    return {"message": "VerdictForge is running!"}

def extract_text(file: UploadFile) -> str:
    """Extract text from uploaded PDF or DOCX"""
    text = ""
    try:
        if file.filename.endswith(".pdf"):
            reader = PyPDF2.PdfReader(file.file)
            for page in reader.pages:
                text += page.extract_text() or ""
        elif file.filename.endswith(".docx"):
            # ⚠️ docx.Document expects a file path or file-like object
            doc = docx.Document(file.file)
            for para in doc.paragraphs:
                text += para.text + "\n"
        else:
            raise ValueError("Unsupported file type. Only PDF and DOCX allowed.")
    except Exception as e:
        raise ValueError(f"Error extracting text: {str(e)}")
    return text.strip()

def summarize_text(text: str) -> str:
    """Send extracted text to OpenRouter and get summary"""
    if not OPENROUTER_API_KEY:
        return "Error: Missing OpenRouter API key. Set it in Render Dashboard > Environment Variables."

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "openai/gpt-4o-mini",  # You can switch to another model available in OpenRouter
        "messages": [
            {"role": "system", "content": "You are a legal assistant that summarizes contracts."},
            {"role": "user", "content": f"Summarize this contract:\n{text}"}
        ]
    }

    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return f"Error contacting OpenRouter API: {str(e)}"

    data = response.json()
    return data.get("choices", [{}])[0].get("message", {}).get("content", "Error: No summary received.")

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
