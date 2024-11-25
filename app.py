from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
from pymongo import MongoClient
import jwt
import bcrypt
import dotenv
import os
import pytz

dotenv.load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client.portfolio
users_collection = db.users
blogs_collection = db.blogs

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

cache_blogs = []

class User(BaseModel):
    username: str
    password: str

class Blog(BaseModel):
    title: str
    content: str

class TokenData(BaseModel):
    token: str

def create_jwt(username: str):
    current_time = datetime.now(pytz.timezone('Asia/Kolkata'))
    expire = current_time + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def validate_jwt(token: str):
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/login")
def login(user: User):
    db_user = users_collection.find_one({"username": user.username})
    if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_jwt(user.username)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/get/blog")
def get_blogs():
    if cache_blogs:
        return cache_blogs
    blogs = blogs_collection.find()
    return [{"id": str(blog["_id"]), "title": blog["title"], "content": blog["content"]} for blog in blogs]

@app.post("/post/blog")
def post_blog(blog: Blog, token: str = Depends(oauth2_scheme)):
    username = validate_jwt(token)
    new_blog = {"title": blog.title, "content": blog.content, "author": username}
    result = blogs_collection.insert_one(new_blog)
    cache_blogs.clear()
    cache_blogs.extend(get_blogs())
    return {"id": str(result.inserted_id), "message": "Blog saved successfully"}

@app.post("/validate")
def validate_token(token_data: TokenData):
    username = validate_jwt(token_data.token)
    return {"username": username, "message": "Token is valid"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)