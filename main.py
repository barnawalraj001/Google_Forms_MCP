import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from tokens import load_tokens, save_tokens

# ======================
# App setup
# ======================

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"

app = FastAPI()

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],
)

# ======================
# Google OAuth config
# ======================

SCOPES = [
    "https://www.googleapis.com/auth/forms.body",
    "https://www.googleapis.com/auth/forms.responses.readonly",
]

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
REDIRECT_URI = f"{BASE_URL}/auth/google/callback"


def get_oauth_flow():
    return Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )


# ======================
# Helpers
# ======================

def get_user_id(payload: dict):
    return payload.get("meta", {}).get("user_id", "default")


def auth_error(id_, user_id):
    return {
        "jsonrpc": "2.0",
        "id": id_,
        "error": {
            "code": 401,
            "message": f"Google Forms not connected for user '{user_id}'. Visit {BASE_URL}/auth/google?user_id={user_id}",
        },
    }


# ======================
# OAuth routes
# ======================

@app.get("/auth/google")
def google_auth(user_id: str = "default"):
    flow = get_oauth_flow()
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        state=user_id,
    )
    return RedirectResponse(auth_url)


@app.get("/auth/google/callback")
def google_callback(request: Request):
    # Guard: Google may hit callback without code
    code = request.query_params.get("code")
    if not code:
        return {"status": "waiting for google authorization"}

    flow = get_oauth_flow()
    flow.fetch_token(authorization_response=request.url._url)

    user_id = request.query_params.get("state", "default")

    tokens = load_tokens()
    existing_refresh = tokens.get(user_id, {}).get("refresh_token")

    tokens[user_id] = {
        "token": flow.credentials.token,
        "refresh_token": flow.credentials.refresh_token or existing_refresh,
    }
    save_tokens(tokens)

    return {"status": "forms connected successfully", "user": user_id}


# ======================
# Google Forms helpers
# ======================

def get_forms_service(user_id: str):
    tokens = load_tokens()
    if user_id not in tokens:
        return None

    creds = Credentials(
        token=tokens[user_id]["token"],
        refresh_token=tokens[user_id]["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=SCOPES,
    )

    return build("forms", "v1", credentials=creds)


def forms_get_form(user_id: str, form_id: str):
    service = get_forms_service(user_id)
    if not service:
        return "AUTH_REQUIRED"

    form = service.forms().get(formId=form_id).execute()

    return {
        "formId": form["formId"],
        "title": form["info"]["title"],
        "documentTitle": form["info"].get("documentTitle"),
    }


def forms_list_responses(user_id: str, form_id: str, max_results: int = 5):
    service = get_forms_service(user_id)
    if not service:
        return "AUTH_REQUIRED"

    res = service.forms().responses().list(
        formId=form_id,
        pageSize=max_results,
    ).execute()

    return res.get("responses", [])


# ======================
# MCP endpoints
# ======================

@app.get("/")
def health():
    return {"status": "Forms MCP running"}


@app.post("/mcp")
async def mcp_handler(request: Request):
    payload = await request.json()
    method = payload.get("method")
    id_ = payload.get("id")
    user_id = get_user_id(payload)

    # ---- initialize ----
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": id_,
            "result": {
                "serverInfo": {
                    "name": "Multi-User Google Forms MCP",
                    "version": "0.1.0",
                }
            },
        }

    # ---- tools/list ----
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": id_,
            "result": {
                "tools": [
                    {
                        "name": "forms.get_form",
                        "description": "Get basic information about a Google Form",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "form_id": {
                                    "type": "string",
                                    "description": "Google Form ID",
                                }
                            },
                            "required": ["form_id"],
                        },
                    },
                    {
                        "name": "forms.list_responses",
                        "description": "List responses of a Google Form",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "form_id": {
                                    "type": "string",
                                    "description": "Google Form ID",
                                },
                                "max_results": {
                                    "type": "integer",
                                    "default": 5,
                                },
                            },
                            "required": ["form_id"],
                        },
                    },
                ]
            },
        }

    # ---- tools/call ----
    if method == "tools/call":
        tool = payload["params"]["name"]
        args = payload["params"].get("arguments", {})

        if tool == "forms.get_form":
            res = forms_get_form(user_id, args["form_id"])
            if res == "AUTH_REQUIRED":
                return auth_error(id_, user_id)
            return {
                "jsonrpc": "2.0",
                "id": id_,
                "result": {"content": [{"type": "json", "json": res}]},
            }

        if tool == "forms.list_responses":
            res = forms_list_responses(
                user_id,
                args["form_id"],
                args.get("max_results", 5),
            )
            if res == "AUTH_REQUIRED":
                return auth_error(id_, user_id)
            return {
                "jsonrpc": "2.0",
                "id": id_,
                "result": {"content": [{"type": "json", "json": res}]},
            }

    return JSONResponse(
        status_code=400,
        content={
            "jsonrpc": "2.0",
            "id": id_,
            "error": {"code": -32601, "message": "Method not found"},
        },
    )
