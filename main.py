from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse
import os
import requests
import PyPDF2
import docx

app = FastAPI()

# Get your OpenRouter API key
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

if not OPENROUTER_API_KEY:
    print("⚠️ Warning: OPENROUTER_API_KEY is not set! Make sure it's added in Render Environment Variables.")

def extract_text_from_file(file: UploadFile):
    """Extract text from PDF or DOCX files"""
    try:
        if file.filename.endswith(".pdf"):
            pdf_reader = PyPDF2.PdfReader(file.file)
            text = "".join(page.extract_text() or "" for page in pdf_reader.pages)
            return text.strip()
        elif file.filename.endswith(".docx"):
            doc = docx.Document(file.file)
            text = "\n".join([para.text for para in doc.paragraphs])
            return text.strip()
        else:
            return None
    except Exception as e:
        print(f"❌ Error extracting text: {e}")
        return None

def analyze_contract(text: str, instruction: str):
    """Send text to OpenRouter for analysis"""
    try:
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": "mistralai/mistral-7b-instruct:free",
            "messages": [
                {"role": "system", "content": "You are a legal contract analyzer."},
                {"role": "user", "content": f"Instruction: {instruction}\n\nContract:\n{text}"},
            ],
        }

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
        )

        print("🔍 OpenRouter Response Code:", response.status_code)
        print("🔍 OpenRouter Response:", response.text[:500])  # show first 500 chars for debugging

        if response.status_code != 200:
            return f"Error: {response.text}"

        data = response.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "No response")
    except Exception as e:
        print(f"❌ Error in analyze_contract: {e}")
        return None

@app.post("/analyze/")
async def analyze(file: UploadFile = File(...), instruction: str = Form("Summarize the contract")):
    text = extract_text_from_file(file)
    if not text:
        return JSONResponse(content={"error": "Failed to extract text from file"}, status_code=400)

    result = analyze_contract(text, instruction)
    if not result:
        return JSONResponse(content={"error": "Failed to analyze file"}, status_code=500)

    return {"contract_summary": result}
