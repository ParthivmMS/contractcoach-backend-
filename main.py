# main.py
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from PyPDF2 import PdfReader
import docx
import openai
import os

# ------------------------------
# CONFIG
# ------------------------------
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")  # set in Render secrets
MODEL_NAME = "gpt-4o-mini"  # adjust if needed

openai.api_key = OPENROUTER_API_KEY

# ------------------------------
# FASTAPI INIT
# ------------------------------
app = FastAPI(title="ContractCoach Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # replace "*" with your frontend domain for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------
# UTILITY: Extract text from file
# ------------------------------
async def extract_text(file: UploadFile):
    filename = file.filename.lower()
    if filename.endswith(".txt"):
        return (await file.read()).decode("utf-8", errors="ignore")
    elif filename.endswith(".docx"):
        doc = docx.Document(file.file)
        return "\n".join([p.text for p in doc.paragraphs])
    elif filename.endswith(".pdf"):
        reader = PdfReader(file.file)
        text = ""
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
        return text
    else:
        return ""

# ------------------------------
# ROUTE: POST /
# ------------------------------
@app.post("/")
async def analyze_contract(file: UploadFile = File(...)):
    try:
        # Step 1: Extract text
        text = await extract_text(file)
        if not text.strip():
            return JSONResponse(
                status_code=400,
                content={"summary": "Unable to extract text from this file."}
            )

        # Step 2: Prepare prompt for OpenRouter
        prompt = f"""
        Summarize the following legal contract clearly and concisely.
        Highlight key clauses, risks, and recommendations.

        Contract Text:
        {text[:5000]}  # limit input for token safety
        """

        # Step 3: Call OpenRouter API
        response = openai.ChatCompletion.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=500
        )

        summary = response['choices'][0]['message']['content']

        # Step 4: Return JSON
        return {"summary": summary}

    except Exception as e:
        print("Error analyzing contract:", e)
        return JSONResponse(
            status_code=500,
            content={"summary": "Failed to analyze file. Please try again later."}
        )

# ------------------------------
# ROUTE: HEALTHCHECK
# ------------------------------
@app.get("/health")
async def healthcheck():
    return {"status": "ok"}
