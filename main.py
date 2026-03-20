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

# ─── ANUNCIOS ───────────────────────────────────────

class Anuncio(BaseModel):
    texto: str

class AnuncioEliminar(BaseModel):
    id: int

class AnuncioActualizar(BaseModel):
    elID: int
    nuevo_texto: str

@app.get("/anuncios")
def obtener_anuncios():
    respuesta = supabase.table("anuncios").select("*").execute()
    return respuesta.data

@app.post("/anuncios")
def agregar_anuncio(anuncio: Anuncio):
    respuesta = supabase.table("anuncios").insert({"texto": anuncio.texto}).execute()
    return respuesta.data

@app.put("/anuncios")
def actualizar_anuncio(anuncio: AnuncioActualizar):
    respuesta = supabase.table("anuncios").update({"texto": anuncio.nuevo_texto}).eq("id", anuncio.elID).execute()
    return respuesta.data

@app.delete("/anuncios")
def eliminar_anuncio(anuncio: AnuncioEliminar):
    respuesta = supabase.table("anuncios").delete().eq("id", anuncio.id).execute()
    return respuesta.data

# ─── CÉLULAS ────────────────────────────────────────

class Celula(BaseModel):
    nombre: str
    lider_email: str = None

@app.get("/celulas")
def obtener_celulas(perfil = Depends(verificar_token)):
    iglesia = supabase.table("perfiles").select("iglesia").eq("id", str(perfil.id)).execute()
    nombre_iglesia = iglesia.data[0]["iglesia"]
    respuesta = supabase.table("celulas").select("*").eq("iglesia", nombre_iglesia).execute()
    return respuesta.data

@app.post("/celulas")
def crear_celula(celula: Celula, perfil = Depends(verificar_rol(["super_admin", "pastor"]))):
    iglesia = supabase.table("perfiles").select("iglesia").eq("id", str(perfil["id"])).execute()
    nombre_iglesia = iglesia.data[0]["iglesia"]
    respuesta = supabase.table("celulas").insert({
        "nombre": celula.nombre,
        "iglesia": nombre_iglesia,
        "lider_email": celula.lider_email
    }).execute()
    return respuesta.data

@app.delete("/celulas/{celula_id}")
def eliminar_celula(celula_id: int, perfil = Depends(verificar_rol(["super_admin", "pastor"]))):
    respuesta = supabase.table("celulas").delete().eq("id", celula_id).execute()
    return respuesta.data

# ─── REPORTES DE CÉLULA ─────────────────────────────

class ReporteCelula(BaseModel):
    celula_id: int
    fecha: str
    miembros_asistentes: int = 0
    miembros_faltantes: int = 0
    padres_espirituales: int = 0
    amigos_contactados: int = 0
    amigos_fiesta: int = 0
    amigos_restauracion: int = 0
    amigos_bautizados: int = 0
    bautizados_etapa1: int = 0
    bautizados_etapa2: int = 0
    bautizados_etapa3: int = 0
    reencuentro: int = 0
    escuela_eco: int = 0
    escuela_ministerios: int = 0
    celula_multiplicarse: bool = False
    padres_espirituales_ncelula: int = 0
    ninos_discipulado: int = 0
    ofrendas_discipulado: float = 0
    miembros_asistentes_alcance: int = 0
    miembros_privilegios: int = 0
    amigos_asistentes: int = 0
    jovenes_asistentes: int = 0
    adolescentes_asistentes: int = 0
    conversiones: int = 0
    ninos_alcance: int = 0
    ofrenda_alcance: float = 0
    miembros_culto: int = 0
    adolescentes_culto: int = 0
    ninos_culto: int = 0
    jovenes_culto: int = 0
    amigos_culto: int = 0
    total_ofrenda: float = 0
    observaciones: str = ""

@app.get("/reportes")
def obtener_reportes(perfil = Depends(verificar_token)):
    respuesta = supabase.table("reportes_celula").select("*, celulas(nombre)").execute()
    return respuesta.data

@app.get("/reportes/{celula_id}")
def obtener_reportes_celula(celula_id: int, perfil = Depends(verificar_token)):
    respuesta = supabase.table("reportes_celula").select("*").eq("celula_id", celula_id).order("fecha", desc=True).execute()
    return respuesta.data

@app.post("/reportes")
def crear_reporte(reporte: ReporteCelula, perfil = Depends(verificar_token)):
    respuesta = supabase.table("reportes_celula").insert(reporte.dict()).execute()
    return respuesta.data