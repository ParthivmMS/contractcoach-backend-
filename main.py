from fastapi import FastAPI, File, UploadFile, Form
import requests
import PyPDF2
import docx

app = FastAPI()

# Replace with your OpenRouter API Key (set in Render Dashboard > Environment Variables)
OPENROUTER_API_KEY = "your_api_key_here"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def extract_text(file: UploadFile) -> str:
    """Extract text from uploaded PDF or DOCX"""
    text = ""
    if file.filename.endswith(".pdf"):
        reader = PyPDF2.PdfReader(file.file)
        for page in reader.pages:
            text += page.extract_text() or ""
    elif file.filename.endswith(".docx"):
        doc = docx.Document(file.file)
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
        "model": "openai/gpt-4o-mini",  # You can change to another model available in OpenRouter
        "messages": [
            {"role": "system", "content": "You are a legal assistant that summarizes contracts."},
            {"role": "user", "content": f"Summarize this contract:\n{text}"}
        ]
    }

    response = requests.post(OPENROUTER_URL, headers=headers, json=payload)

    if response.status_code != 200:
        return f"Error: {response.text}"

    data = response.json()
    # ✅ OpenRouter always returns inside choices[0]["message"]["content"]
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
