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
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
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
    
# Verificar rol específico
def verificar_rol(roles_permitidos: list):
    def verificador(usuario = Depends(verificar_token)):
        perfil = supabase.table("perfiles").select("*").eq("id", str(usuario.id)).execute()
        rol = perfil.data[0]["rol"]
        if rol not in roles_permitidos:
            raise HTTPException(status_code=403, detail=f"Necesitas ser: {roles_permitidos}")
        return perfil.data[0]
    return verificador

# Ruta protegida — solo con token válido
@app.get("/perfil")
def obtener_perfil(usuario = Depends(verificar_token)):
    perfil = supabase.table("perfiles").select("*").eq("id", str(usuario.id)).execute()
    return perfil.data[0]

# Solo super_admin puede ver todas las iglesias
@app.get("/iglesias")
def obtener_iglesias(perfil = Depends(verificar_rol(["super_admin"]))):
    iglesias = supabase.table("perfiles").select("iglesia").execute()
    return iglesias.data

# Solo super_admin y pastor pueden crear miembros
@app.post("/miembros")
def crear_miembro(datos: LoginData, perfil = Depends(verificar_rol(["super_admin", "pastor"]))):
    try:
        # Crear usuario en Supabase Auth
        nuevo_usuario = supabase_admin.auth.admin.create_user({
            "email": datos.email,
            "password": datos.password,
            "email_confirm": True
        })

        # Crear perfil con rol miembro
        supabase.table("perfiles").insert({
            "id": str(nuevo_usuario.user.id),
            "email": datos.email,
            "rol": "miembro",
            "iglesia": perfil["iglesia"]
        }).execute()

        return {"mensaje": "Miembro creado", "email": datos.email}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Todos los roles autenticados pueden ver miembros de su iglesia
@app.get("/miembros")
def obtener_miembros(perfil = Depends(verificar_rol(["super_admin", "pastor", "lider_celula"]))):
    miembros = supabase.table("perfiles").select("*").eq("iglesia", perfil["iglesia"]).execute()
    return miembros.data