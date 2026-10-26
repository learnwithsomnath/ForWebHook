from fastapi import FastAPI, Request, Header, HTTPException
import hmac 
import hashlib 
import os
import uvicorn
app = FastAPI() 
GITHUB_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "your_webhook_secret")  # Set GITHUB_WEBHOOK_SECRET to your actual secret
def verify_signature(payload, signature): 
    """Verify GitHub's signature to ensure request authenticity""" 
    if not signature:
        return False
    mac = hmac.new(GITHUB_SECRET.encode(), payload, hashlib.sha256)
    expected_signature = "sha256=" + mac.hexdigest() 
    return hmac.compare_digest(expected_signature, signature) 
@app.post("/github-webhook") 
async def github_webhook(request: Request, x_hub_signature_256: str = Header(None)): 
    payload = await request.body()     
    # Verify webhook signature 
    if not verify_signature(payload, x_hub_signature_256): 
        raise HTTPException(status_code=401, detail="Invalid signature")
    data = await request.json() 
    event_type = request.headers.get("X-GitHub-Event") 
    print(f"Received GitHub Webhook - Event: {event_type}") 
    print(f"Payload: {data}") 
    return {"message": "Webhook received"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
