from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from PyPDF2 import PdfReader
import docx
import openai  # or replace with requests for Mistral API
import uvicorn
import os

app = FastAPI()

# CORS for your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # replace "*" with your frontend URL
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set your API key as environment variable on Render
openai.api_key = os.getenv("OPENAI_API_KEY")

def extract_text(file: UploadFile):
    if file.filename.endswith(".txt"):
        return file.file.read().decode("utf-8")
    elif file.filename.endswith(".pdf"):
        reader = PdfReader(file.file)
        text = ""
        for page in reader.pages:
            text += page.extract_text()
        return text
    elif file.filename.endswith(".docx"):
        doc = docx.Document(file.file)
        text = "\n".join([para.text for para in doc.paragraphs])
        return text
    else:
        return None

def call_ai_model(contract_text: str):
    # Call OpenAI / Mistral to summarize/analyze contract
    prompt = f"Analyze this contract and summarize risks in simple language:\n\n{contract_text}"

    response = openai.ChatCompletion.create(
        model="gpt-4",  # or gpt-3.5-turbo
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=500
    )

    summary = response.choices[0].message.content
    return {"summary": summary}

@app.post("/analyze")
async def analyze_contract(file: UploadFile = File(...)):
    text = extract_text(file)
    if text is None:
        return {"error": "Unsupported file type. Upload TXT, PDF, or DOCX."}

    analysis = call_ai_model(text)
    return analysis

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
