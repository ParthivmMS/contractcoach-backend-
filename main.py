from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse
import requests
import PyPDF2
import docx

app = FastAPI()

# Replace with your real OpenRouter API key
OPENROUTER_API_KEY = "your_openrouter_api_key"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def extract_text_from_pdf(file):
    """Extracts text from uploaded PDF"""
    reader = PyPDF2.PdfReader(file)
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
    return text


def extract_text_from_docx(file):
    """Extracts text from uploaded DOCX"""
    doc = docx.Document(file)
    text = ""
    for para in doc.paragraphs:
        text += para.text + "\n"
    return text


@app.post("/summarize_contract/")
async def summarize_contract(file: UploadFile = File(...)):
    # Step 1: Extract text
    if file.filename.endswith(".pdf"):
        contract_text = extract_text_from_pdf(file.file)
    elif file.filename.endswith(".docx"):
        contract_text = extract_text_from_docx(file.file)
    else:
        return JSONResponse(content={"error": "Unsupported file format"}, status_code=400)

    # Step 2: Call OpenRouter API
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "mistralai/mistral-7b-instruct",  # you can switch to another model if you want
        "messages": [
            {"role": "system", "content": "You are a legal AI assistant that summarizes contracts clearly and concisely."},
            {"role": "user", "content": contract_text}
        ]
    }

    response = requests.post(OPENROUTER_URL, headers=headers, json=payload)

    if response.status_code != 200:
        return JSONResponse(content={"error": "API request failed", "details": response.text}, status_code=500)

    data = response.json()

    try:
        # ✅ Correct way to extract summary from OpenRouter
        summary = data["choices"][0]["message"]["content"]
    except Exception as e:
        return JSONResponse(content={"error": "Failed to parse response", "details": str(e), "raw": data}, status_code=500)

    # Step 3: Return summary
    return {"contract_summary": summary}
