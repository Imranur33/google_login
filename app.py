import os
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from oauthlib.oauth2 import WebApplicationClient
import requests
import uuid


REDIRECT_URI = "http://127.0.0.1:8000/auth/google/callback"

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

app = FastAPI()

# Add Session Middleware
app.add_middleware(SessionMiddleware, secret_key="your_secret_key")

# Add CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (adjust as needed for your use case)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

templates = Jinja2Templates(directory="templates")

# Google API endpoints
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

# Create an OAuth 2.0 client
client = WebApplicationClient(CLIENT_ID)

@app.get("/auth/google/login")
async def google_login(request: Request):
    state = str(uuid.uuid4())
    request.session["state"] = state

    authorization_url = client.prepare_request_uri(
        AUTHORIZATION_URL,
        redirect_uri=REDIRECT_URI,
        scope=["profile", "email"],
        state=state,
    )

    return RedirectResponse(authorization_url)

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    code = request.query_params.get('code')
    state = request.query_params.get('state')

    if not code or not state:
        raise HTTPException(status_code=400, detail="Invalid callback request")

    if state != request.session.get("state"):
        raise HTTPException(status_code=400, detail="Invalid state")

    # Exchange authorization code for an access token
    token_url, headers, body = client.prepare_token_request(
        TOKEN_URL,
        authorization_response=str(request.url),  # Ensure URL is a string
        redirect_url=REDIRECT_URI,
        code=code
    )

    token_response = requests.post(token_url, headers=headers, data=body, auth=(CLIENT_ID, CLIENT_SECRET))
    client.parse_request_body_response(token_response.text)

    # Get user info
    userinfo_endpoint = client.add_token(USERINFO_URL)
    userinfo_response = requests.get(userinfo_endpoint)
    user_info = userinfo_response.json()

    return templates.TemplateResponse("profile.html", {"request": request, "user_info": user_info})
