from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from supabase import create_client
from dotenv import load_dotenv
from jose import jwt, JWTError
import os

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
security = HTTPBearer()

# Modelos
class LoginData(BaseModel):
    email: str
    password: str

# Login
@app.post("/login")
def login(datos: LoginData):
    try:
        respuesta = supabase.auth.sign_in_with_password({
            "email": datos.email,
            "password": datos.password
        })
        usuario = respuesta.user
        token = respuesta.session.access_token

        # Obtener perfil con rol
        perfil = supabase.table("perfiles").select("*").eq("id", str(usuario.id)).execute()

        return {
            "token": token,
            "email": usuario.email,
            "rol": perfil.data[0]["rol"],
            "iglesia": perfil.data[0]["iglesia"]
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

# Verificar token
def verificar_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = supabase.auth.get_user(token)
        return payload.user
    except:
        raise HTTPException(status_code=401, detail="Token inválido")

# Ruta protegida — solo con token válido
@app.get("/perfil")
def obtener_perfil(usuario = Depends(verificar_token)):
    perfil = supabase.table("perfiles").select("*").eq("id", str(usuario.id)).execute()
    return perfil.data[0]