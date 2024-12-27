import jwt

secret = "mysecret"
algo = "HS256"

def generate_jwt():
   return (jwt.encode({"id": "1"}, secret, algorithm=algo))

def validate_jwt(_jwt):
    try:
        jwt.decode(_jwt, secret , algorithms=[algo])
        return True
    except Exception as e:
        print(e)
        return False
    
def get_jwt(_jwt):
    try:
        decode = jwt.decode(_jwt, secret , algorithms=[algo])
        return decode["id"]
        
    except Exception as e:
        print(e)
        return False