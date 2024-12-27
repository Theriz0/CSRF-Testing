# CSRF-Testing

Python packages installation: 

python -m pip install jwt   
python -m pip install fastapi

Running the application in dev environment:

fastapi dev main.py 

Flowchart for updating a Profile's Email in the database:
1. profile.html (http://127.0.0.1:8000/profile) requests a CSRF token.
2. CSRF token is loaded in javascript NOT saved in browser storage or cookies
3. profile.html requests JWT for user
4. JWT is saved in cookies
5. User clicks "Change Profile Email Safe" and a request is sent to /profile/change-email-safe API
6. change-email-safe API validates JWT
7. JWT is valid
8. change-email-safe API validates CSRF Token
9. CSRF Token is Valid and Email is Changed
10. Response is sent to client
