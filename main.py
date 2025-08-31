import os
from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI

app = FastAPI()

# Allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Use OpenRouter API key
client = OpenAI(api_key=os.getenv("OPENROUTER_API_KEY"), base_url="https://openrouter.ai/api/v1")

@app.post("/analyze")
async def analyze(file: UploadFile):
    try:
        content = await file.read()
        text = content.decode("utf-8")

        # Call OpenRouter (Mistral model)
        response = client.chat.completions.create(
            model="mistralai/mistral-7b-instruct",
            messages=[
                {"role": "system", "content": "You are a legal assistant that summarizes contracts into plain English."},
                {"role": "user", "content": f"Summarize this contract:\n\n{text}"}
            ]
        )

        summary = response.choices[0].message.content
        return {"summary": summary}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing contract: {str(e)}")
