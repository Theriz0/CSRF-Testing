from fastapi import FastAPI, Response, Request
from pydantic import BaseModel
from uuid import uuid4
from fastapi.responses import HTMLResponse
from my_jwt import generate_jwt, validate_jwt, get_jwt

class GenerateCSRFBody(BaseModel):
    id:str

class GenerateJWTBody(BaseModel):
    id:str

csrfTracker = {}

accountDB = {
    '1':{
        'email':'theriz0@gmail.com'
    }
}

app = FastAPI()

# Get Account Email based on ID in JWT
@app.get("/profile/account-email")
async def account_email(request:Request, response:Response):
    _jwt = request.headers.get('cookie').split("=")[1]
    if validate_jwt(_jwt):
        id = get_jwt(_jwt)
        if(id in accountDB):
            return accountDB[id]['email']

# Generate CSRF Token and store in CSRF Tracker
@app.post("/generate-csrf")
async def generate_csrf(generateCSRFBody: GenerateCSRFBody):
    csrfToken = uuid4()
    csrfTracker[generateCSRFBody.id] = {"csrfToken":str(csrfToken)}
    return({"csrfToken":str(csrfToken)})

# Change Email without CSRF Token
@app.post("/profile/change-email-vulnerable")
async def change_email_vulnerable(request:Request, response:Response):
    response.headers.append("Access-Control-Allow-Origin","*")

    if (request.headers['content-type'] == 'application/x-www-form-urlencoded'):
        body = await request.body()
        decoded_body = body.decode()
        email = decoded_body.split("=")[1]

    elif (request.headers['content-type'] == 'application/json'):
        body = await request.json()
        email = body['email']

    else:
        response.status_code = 400
        return "Unaccepted content-type"
    
    _jwt = request.headers.get('cookie').split("=")[1]

    if validate_jwt(_jwt):
        id = get_jwt(_jwt)
        if(id in accountDB):
            accountDB[id]['email'] = email
        else:
            response.status_code = 418
            return "Im a teapot"
    else:
        response.status_code = 401
        return "invalid jwt"

@app.post("/profile/change-email-safe")
async def change_email_safe(request:Request, response: Response):

    if (request.headers['content-type'] == 'application/x-www-form-urlencoded'):
        body = await request.body()
        decoded_body = body.decode()
        email = decoded_body.split("=")[1]

    elif (request.headers['content-type'] == 'application/json'):
        body = await request.json()
        email = body['email']

    else:
        response.status_code = 400
        return "Unaccepted content-type"
    
    _jwt = request.headers.get('cookie').split("=")[1]

    # Validate JWT hasn't been tampered with
    if validate_jwt(_jwt):
        id = get_jwt(_jwt)

        csrf_token = request.headers.get('csrf-token')

        # Validate id has a CSRF Token and that the id's token matches what is sent in the headers.
        if (id in csrfTracker and csrf_token == csrfTracker[id]["csrfToken"]):
            if(id in accountDB):
                accountDB[id]['email'] = email
            else:
                response.status_code = 418
                return "Im a teapot"
            return "1"
        else:
            response.status_code = 418
            return "Im a teapot - CSRF PREVENTION"
        
    else:
        response.status_code = 401
        return "invalid jwt"
    
@app.options("/profile/change-email-safe")
async def cors_pre_flight(response:Response):
    response.headers.append("Access-Control-Allow-Origin","*")
    response.headers.append("Access-Control-Allow-Methods", "POST")
    response.headers.append("Access-Control-Allow-Headers", "content-type")
    return

# Returns Profile.html + injects _jwt cookie into the browser on page load 
@app.get("/profile", response_class=HTMLResponse)
async def profile(response: Response):
    with open("./profile.html", 'r') as file:
        profileHTML = file.read()

    jwt = generate_jwt()
    print(jwt)

    # samesite="none" -> browser sends the cookie with both cross-site and same-site requests.
    # samesite="lax" -> cookie is not sent on cross-site requests, such as on requests to load images or frames,
    # samesite="strict" ->  browser sends the cookie only for same-site requests, that is, requests originating from the same site that set the cookie
    # secure indicates that the cookie is sent to the server only when a request is made with the https:
    response.set_cookie(key="_jwt", value=jwt, samesite="none", secure=True)
    return profileHTML
