from fastapi import FastAPI, File, UploadFile
import requests
import PyPDF2
import docx
import io
import os

app = FastAPI()

# ✅ Get API key from Render environment variable
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def extract_text(file: UploadFile) -> str:
    """Extract text from uploaded PDF or DOCX"""
    text = ""
    file_bytes = file.file.read()  # read as bytes
    file.file.seek(0)  # reset pointer so libraries can read it again

    if file.filename.endswith(".pdf"):
        try:
            reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
            for page in reader.pages:
                text += page.extract_text() or ""
        except Exception as e:
            raise ValueError(f"PDF extraction failed: {str(e)}")

    elif file.filename.endswith(".docx"):
        try:
            doc = docx.Document(io.BytesIO(file_bytes))
            for para in doc.paragraphs:
                text += para.text + "\n"
        except Exception as e:
            raise ValueError(f"DOCX extraction failed: {str(e)}")

    else:
        raise ValueError("Unsupported file type. Only PDF and DOCX allowed.")

    return text.strip()


def summarize_text(text: str) -> str:
    """Send extracted text to OpenRouter and get summary"""
    if not OPENROUTER_API_KEY:
        return "Error: Missing OpenRouter API Key."

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "openai/gpt-4o-mini",  # can change model if needed
        "messages": [
            {"role": "system", "content": "You are a legal assistant that summarizes contracts."},
            {"role": "user", "content": f"Summarize this contract:\n{text}"}
        ]
    }

    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "Error: no summary")
    except Exception as e:
        return f"OpenRouter request failed: {str(e)}"


@app.post("/summarize/")
async def summarize_contract(file: UploadFile = File(...)):
    try:
        text = extract_text(file)
        if not text:
            return {"summary": "Error: could not extract text (empty)"}
        summary = summarize_text(text)
        return {"summary": summary}
    except Exception as e:
        # ✅ Now returns detailed error instead of vague one
        return {"summary": f"Failed to analyze file: {str(e)}"}
