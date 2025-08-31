from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from PyPDF2 import PdfReader
from docx import Document
import requests

import os

app = FastAPI()

# Allow your frontend to call the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change this to your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Your OpenRouter API Key
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")  # Set in Render as environment variable
OPENROUTER_MODEL = "mistral-7b-instruct"  # or whichever model you want

def extract_text(file: UploadFile) -> str:
    content = ""
    if file.filename.lower().endswith(".pdf"):
        pdf = PdfReader(file.file)
        for page in pdf.pages:
            content += page.extract_text() or ""
    elif file.filename.lower().endswith((".doc", ".docx")):
        doc = Document(file.file)
        for para in doc.paragraphs:
            content += para.text + "\n"
    elif file.filename.lower().endswith(".txt"):
        content = file.file.read().decode("utf-8")
    return content

def call_openrouter(prompt: str) -> str:
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500
    }
    response = requests.post(url, json=data, headers=headers)
    response_json = response.json()
    # Extract text from response
    return response_json['choices'][0]['message']['content']

@app.post("/")
async def analyze_file(file: UploadFile = File(...)):
    try:
        text = extract_text(file)
        if not text.strip():
            return {"summary": "No text found in the document."}

        prompt = f"Summarize this contract text briefly:\n\n{text}"
        summary = call_openrouter(prompt)
        return {"summary": summary}
    except Exception as e:
        return {"summary": f"Error: {str(e)}"}
