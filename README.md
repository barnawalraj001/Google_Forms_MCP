# Google_Forms_MCP

## Deploy (Railway)

1. Deploy this repo on Railway
2. Add these environment variables:

GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
BASE_URL=https://your-app-name.up.railway.app

yaml
Copy code

3. Deploy the project

---

## Connect Google Account

Open in browser:

https://your-app-name.up.railway.app/auth/google?user_id=xyz


---

## MCP Endpoint

Use this endpoint to connect MCP:

https://your-app-name.up.railway.app/mcp



---

## Using Tools

Pass `user_id` in every MCP request:

```json
{
  "meta": {
    "user_id": "xyz"
  }
}# Google_Forms_MCP
