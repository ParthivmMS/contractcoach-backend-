import os
import requests
from fastapi import FastAPI, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from PyPDF2 import PdfReader
from docx import Document

app = FastAPI()

# Allow CORS (so frontend can talk to backend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def extract_text_from_file(file: UploadFile) -> str:
    if file.filename.endswith(".pdf"):
        pdf_reader = PdfReader(file.file)
        return " ".join(page.extract_text() or "" for page in pdf_reader.pages)
    elif file.filename.endswith(".docx"):
        doc = Document(file.file)
        return " ".join(paragraph.text for paragraph in doc.paragraphs)
    else:
        return file.file.read().decode("utf-8")

def summarize_text(text: str) -> str:
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": "mistralai/mistral-7b-instruct",  # You can switch models
        "messages": [
            {"role": "system", "content": "You are a legal document summarizer."},
            {"role": "user", "content": f"Summarize this contract:\n\n{text}"}
        ],
    }

    response = requests.post(OPENROUTER_URL, headers=headers, json=payload)

    try:
        data = response.json()
    except Exception:
        return f"Error: Could not parse JSON. Raw response: {response.text}"

    # ✅ Safely extract response
    if "choices" in data and len(data["choices"]) > 0:
        return data["choices"][0]["message"]["content"].strip()
    else:
        # Debugging output
        return f"Error: Unexpected response format.\n\n{data}"

@app.post("/summarize/")
async def summarize_contract(file: UploadFile, task: str = Form("summarize")):
    text = extract_text_from_file(file)
    summary = summarize_text(text)
    return {"summary": summary}
