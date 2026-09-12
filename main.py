from dotenv import load_dotenv
load_dotenv()

import io
import traceback
from typing import Optional, List
import pandas as pd

from fastapi import FastAPI, Depends, HTTPException, status, Request, File, UploadFile, Query
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session
from sqlalchemy import or_, func

from database import engine, Base, SessionLocal, get_db
from models import Usuario, Rol, Producto, MovimientoInventario, AuditoriaLog, NombreRol, TipoAccion, TipoMovimiento
from auth import (
    hash_password, verify_password, create_access_token,
    get_usuario_actual, verificar_roles
)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Sistema Logístico de Inventario Metalmecánica",
    version="2.0.0"
)


# --- MANEJO GLOBAL DE ERRORES NO CONTROLADOS ---
# Antes, cualquier excepción no capturada (AttributeError, IntegrityError, etc.)
# hacía que Starlette devolviera texto plano ("Internal Server Error"), lo cual
# rompía el frontend con el error "Unexpected token 'I'... is not valid JSON",
# porque el JS siempre espera poder hacer res.json() sobre la respuesta.
# Con este handler, cualquier error no previsto también devuelve JSON válido,
# y además queda registrado en la consola con el traceback completo para debug.
@app.exception_handler(Exception)
async def manejador_errores_globales(request: Request, exc: Exception):
    print("ERROR NO CONTROLADO:")
    print(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={"detail": "Ocurrió un error interno en el servidor. Contacta al administrador."}
    )


@app.on_event("startup")
def crear_usuario_admin_inicial():
    db = SessionLocal()
    try:
        rol_admin = db.query(Rol).filter(Rol.id == 1).first()
        if not rol_admin:
            db.add(Rol(id=1, nombre=NombreRol.ADMIN))
            db.add(Rol(id=2, nombre=NombreRol.COORDINADOR))
            db.add(Rol(id=3, nombre=NombreRol.OPERARIO))
            db.commit()

        usuario_admin = db.query(Usuario).filter(func.upper(Usuario.username) == "ADMIN").first()
        if not usuario_admin:
            admin_user = Usuario(
                username="ADMIN",
                email="ADMIN@EMPRESA.COM",
                password_hash=hash_password("1"),
                rol_id=1,
                activo=True
            )
            db.add(admin_user)
            db.commit()
    except Exception as e:
        print(f"Error inicializando admin: {e}")
    finally:
        db.close()


def registrar_auditoria(db: Session, usuario_id: Optional[int], accion: TipoAccion, tabla: str, ip: str, detalles: str):
    log = AuditoriaLog(
        usuario_id=usuario_id,
        accion=accion,
        tabla_afectada=tabla,
        ip_origen=ip,
        detalles=detalles.upper()
    )
    db.add(log)
    db.commit()


# --- SCHEMAS PYDANTIC ---
# Usuarios: SIN conversión a mayúsculas. Username, email y password
# se guardan tal cual los escribe la persona (decisión explícita:
# estos son datos de identidad, no de catálogo).
class UsuarioCrear(BaseModel):
    username: str
    email: Optional[str] = None
    password: str
    rol_id: int


class UsuarioEditar(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    rol_id: Optional[int] = None


# Productos: SÍ se normalizan a mayúsculas, para evitar duplicados
# de catálogo tipo "tornillo" vs "TORNILLO" vs "Tornillo".
class ProductoCrear(BaseModel):
    codigo_sku: str
    nombre: str
    descripcion: Optional[str] = None
    categoria: str = "GENERAL"
    padre_sku: Optional[str] = None
    stock_actual: int = Field(default=0, ge=0)
    unidad_medida: str = Field(default="UND")
    stock_minimo: int = Field(default=5, ge=0)
    precio_unitario: float = Field(default=0.0, ge=0.0)

    @validator('codigo_sku', 'nombre', 'descripcion', 'categoria', 'padre_sku', 'unidad_medida', pre=True)
    def convertir_mayusculas(cls, v):
        return v.upper() if isinstance(v, str) else v


class MovimientoCrear(BaseModel):
    codigo_sku: str
    cantidad: int = Field(gt=0)
    tipo: TipoMovimiento
    observacion: Optional[str] = None

    @validator('codigo_sku', 'observacion', pre=True)
    def convertir_mayusculas(cls, v):
        return v.upper() if isinstance(v, str) else v


# --- AUTENTICACIÓN ---
@app.post("/login")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ip_client = request.client.host

    # Búsqueda case-insensitive: "juan", "Juan" y "JUAN" encuentran
    # el mismo registro, sin importar cómo se haya guardado originalmente.
    usuario = db.query(Usuario).filter(func.upper(Usuario.username) == form_data.username.upper()).first()

    if not usuario or not verify_password(form_data.password, usuario.password_hash):
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")

    if not usuario.activo:
        raise HTTPException(status_code=403, detail="Este usuario está desactivado")

    token = create_access_token(data={"sub": usuario.username, "rol": usuario.rol.nombre.value})
    registrar_auditoria(db, usuario.id, TipoAccion.LOGIN, "USUARIOS", ip_client, f"LOGIN EXITOSO: {usuario.username}")

    return {"access_token": token, "token_type": "bearer", "rol": usuario.rol.nombre.value}


# --- CRUD USUARIOS ---
@app.get("/admin/usuarios")
def listar_usuarios(db: Session = Depends(get_db), admin: Usuario = Depends(verificar_roles([NombreRol.ADMIN]))):
    usuarios = db.query(Usuario).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email or "-",
            "rol": u.rol.nombre.value,
            "rol_id": u.rol_id,
            "activo": u.activo
        } for u in usuarios
    ]


@app.post("/admin/usuarios")
def crear_usuario(datos: UsuarioCrear, request: Request, db: Session = Depends(get_db), admin: Usuario = Depends(verificar_roles([NombreRol.ADMIN]))):
    # Verificación de duplicados case-insensitive: "juan" y "Juan"
    # cuentan como el mismo usuario, aunque el campo username no tenga
    # unique constraint case-insensitive a nivel de columna en SQLite.
    existe = db.query(Usuario).filter(func.upper(Usuario.username) == datos.username.upper()).first()
    if existe:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya existe")

    nuevo_user = Usuario(
        username=datos.username,
        email=datos.email,
        password_hash=hash_password(datos.password),
        rol_id=datos.rol_id,
        activo=True
    )
    db.add(nuevo_user)
    db.commit()
    registrar_auditoria(db, admin.id, TipoAccion.CREAR, "USUARIOS", request.client.host, f"CREÓ USUARIO {datos.username}")
    return {"mensaje": "Usuario creado exitosamente"}


@app.put("/admin/usuarios/{usuario_id}")
def editar_usuario(usuario_id: int, datos: UsuarioEditar, request: Request, db: Session = Depends(get_db), admin: Usuario = Depends(verificar_roles([NombreRol.ADMIN]))):
    u = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if datos.email is not None:
        u.email = datos.email
    if datos.rol_id is not None:
        u.rol_id = datos.rol_id
    if datos.password:
        u.password_hash = hash_password(datos.password)

    db.commit()
    registrar_auditoria(db, admin.id, TipoAccion.MODIFICAR, "USUARIOS", request.client.host, f"ACTUALIZÓ USUARIO ID {usuario_id}")
    return {"mensaje": "Usuario actualizado"}


@app.delete("/admin/usuarios/{usuario_id}")
def eliminar_usuario(usuario_id: int, request: Request, db: Session = Depends(get_db), admin: Usuario = Depends(verificar_roles([NombreRol.ADMIN]))):
    u = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if u.username.upper() == "ADMIN":
        raise HTTPException(status_code=400, detail="No se puede eliminar el usuario ADMIN principal")

    db.delete(u)
    db.commit()
    registrar_auditoria(db, admin.id, TipoAccion.ELIMINAR, "USUARIOS", request.client.host, f"ELIMINÓ USUARIO ID {usuario_id}")
    return {"mensaje": "Usuario eliminado correctamente"}


# --- INVENTARIO ---
@app.get("/productos")
def listar_productos(
    buscar: Optional[str] = None,
    categoria: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_usuario_actual)
):
    query = db.query(Producto)

    if buscar:
        term = f"%{buscar.upper()}%"
        query = query.filter(or_(Producto.codigo_sku.like(term), Producto.nombre.like(term)))

    if categoria and categoria != "TODAS":
        query = query.filter(Producto.categoria == categoria.upper())

    total = query.count()
    productos = query.offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "paginas_totales": (total + limit - 1) // limit,
        "datos": [
            {
                "id": p.id,
                "codigo_sku": p.codigo_sku,
                "nombre": p.nombre,
                "descripcion": p.descripcion or "",
                "categoria": p.categoria,
                "padre_sku": p.padre_sku or "-",
                "stock_actual": p.stock_actual,
                "unidad_medida": p.unidad_medida,
                "stock_minimo": p.stock_minimo,
                "precio_unitario": p.precio_unitario
            } for p in productos
        ]
    }


@app.post("/productos")
def crear_producto(p: ProductoCrear, request: Request, db: Session = Depends(get_db), user: Usuario = Depends(verificar_roles([NombreRol.ADMIN, NombreRol.COORDINADOR]))):
    if db.query(Producto).filter(Producto.codigo_sku == p.codigo_sku).first():
        raise HTTPException(status_code=400, detail="El SKU ya existe")

    nuevo = Producto(**p.model_dump())
    db.add(nuevo)
    db.commit()
    registrar_auditoria(db, user.id, TipoAccion.CREAR, "PRODUCTOS", request.client.host, f"CREÓ PRODUCTO SKU {nuevo.codigo_sku}")
    return {"mensaje": "Producto creado con éxito"}


@app.put("/productos/{codigo_sku}")
def editar_producto(codigo_sku: str, p: ProductoCrear, request: Request, db: Session = Depends(get_db), user: Usuario = Depends(verificar_roles([NombreRol.ADMIN, NombreRol.COORDINADOR]))):
    prod = db.query(Producto).filter(Producto.codigo_sku == codigo_sku.upper()).first()
    if not prod:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    prod.nombre = p.nombre
    prod.descripcion = p.descripcion
    prod.categoria = p.categoria
    prod.padre_sku = p.padre_sku
    prod.unidad_medida = p.unidad_medida
    prod.stock_minimo = p.stock_minimo
    prod.precio_unitario = p.precio_unitario

    db.commit()
    registrar_auditoria(db, user.id, TipoAccion.MODIFICAR, "PRODUCTOS", request.client.host, f"EDITÓ PRODUCTO SKU {codigo_sku}")
    return {"mensaje": "Producto actualizado"}


@app.delete("/productos/{codigo_sku}")
def eliminar_producto(codigo_sku: str, request: Request, db: Session = Depends(get_db), user: Usuario = Depends(verificar_roles([NombreRol.ADMIN, NombreRol.COORDINADOR]))):
    prod = db.query(Producto).filter(Producto.codigo_sku == codigo_sku.upper()).first()
    if not prod:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    db.delete(prod)
    db.commit()
    registrar_auditoria(db, user.id, TipoAccion.ELIMINAR, "PRODUCTOS", request.client.host, f"ELIMINÓ PRODUCTO SKU {codigo_sku}")
    return {"mensaje": "Producto eliminado"}


# --- HISTORIAL POR ÍTEM ---
@app.get("/productos/{codigo_sku}/historial")
def historial_producto(codigo_sku: str, db: Session = Depends(get_db), user: Usuario = Depends(get_usuario_actual)):
    prod = db.query(Producto).filter(Producto.codigo_sku == codigo_sku.upper()).first()
    if not prod:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    movs = db.query(MovimientoInventario).filter(MovimientoInventario.producto_id == prod.id).order_by(MovimientoInventario.fecha_registro.desc()).all()
    return [
        {
            "id": m.id,
            "tipo": m.tipo.value,
            "cantidad": m.cantidad,
            "usuario": m.usuario.username,
            "observacion": m.observacion or "-",
            "fecha": m.fecha_registro.isoformat()
        } for m in movs
    ]


# --- REGISTRO DE MOVIMIENTO ---
# --- SCHEMAS PYDANTIC ---
# (el resto de los schemas queda igual, solo se agregan estos dos)

class MovimientoItem(BaseModel):
    codigo_sku: str
    cantidad: int = Field(gt=0)
    tipo: TipoMovimiento
    observacion: Optional[str] = None

    @validator('codigo_sku', 'observacion', pre=True)
    def convertir_mayusculas(cls, v):
        return v.upper() if isinstance(v, str) else v


class MovimientosLoteCrear(BaseModel):
    movimientos: List[MovimientoItem]


# --- REGISTRO DE MOVIMIENTOS (por lote) ---
@app.post("/inventario/movimientos")
def registrar_movimientos(
    lote: MovimientosLoteCrear,
    request: Request,
    db: Session = Depends(get_db),
    user: Usuario = Depends(verificar_roles([NombreRol.ADMIN, NombreRol.COORDINADOR, NombreRol.OPERARIO]))
):
    if not lote.movimientos:
        raise HTTPException(status_code=400, detail="Debes incluir al menos un movimiento")

    # --- PASADA 1: VALIDAR TODO ANTES DE APLICAR NADA ---
    # Se calcula el stock "proyectado" por SKU (por si el mismo SKU
    # aparece más de una vez en el lote) sin tocar la base de datos todavía.
    # Si algo falla acá, se corta con un error y no se modificó nada.
    stock_proyectado = {}
    productos_por_sku = {}

    for idx, m in enumerate(lote.movimientos, start=1):
        prod = db.query(Producto).filter(Producto.codigo_sku == m.codigo_sku).first()
        if not prod:
            raise HTTPException(status_code=404, detail=f"Movimiento #{idx}: producto '{m.codigo_sku}' no encontrado")

        productos_por_sku[prod.codigo_sku] = prod
        actual = stock_proyectado.get(prod.codigo_sku, prod.stock_actual)

        if m.tipo == TipoMovimiento.SALIDA:
            if actual < m.cantidad:
                raise HTTPException(
                    status_code=400,
                    detail=f"Movimiento #{idx}: stock insuficiente para '{prod.codigo_sku}' (disponible: {actual}, solicitado: {m.cantidad})"
                )
            actual -= m.cantidad
        elif m.tipo == TipoMovimiento.INGRESO:
            actual += m.cantidad
        elif m.tipo == TipoMovimiento.AJUSTE:
            actual = m.cantidad

        stock_proyectado[prod.codigo_sku] = actual

    # --- PASADA 2: APLICAR LOS CAMBIOS YA VALIDADOS ---
    resultados = []
    for m in lote.movimientos:
        prod = productos_por_sku[m.codigo_sku]

        if m.tipo == TipoMovimiento.SALIDA:
            prod.stock_actual -= m.cantidad
            accion = TipoAccion.SALIDA_STOCK
        elif m.tipo == TipoMovimiento.INGRESO:
            prod.stock_actual += m.cantidad
            accion = TipoAccion.INGRESO_STOCK
        elif m.tipo == TipoMovimiento.AJUSTE:
            prod.stock_actual = m.cantidad
            accion = TipoAccion.AJUSTE_STOCK

        nuevo_mov = MovimientoInventario(
            producto_id=prod.id,
            usuario_id=user.id,
            tipo=m.tipo,
            cantidad=m.cantidad,
            observacion=m.observacion
        )
        db.add(nuevo_mov)
        registrar_auditoria(db, user.id, accion, "MOVIMIENTOS", request.client.host, f"{m.tipo.value} DE {m.cantidad} EN {prod.codigo_sku}")
        resultados.append({"codigo_sku": prod.codigo_sku, "stock_actual": prod.stock_actual})

    db.commit()
    return {
        "mensaje": f"{len(lote.movimientos)} movimiento(s) registrado(s) correctamente",
        "resultados": resultados
    }


# --- PLANTILLA DE CARGA MASIVA ---
@app.get("/productos/plantilla-excel")
def descargar_plantilla_excel(user: Usuario = Depends(verificar_roles([NombreRol.ADMIN, NombreRol.COORDINADOR]))):
    data = [{
        "codigo_sku": "PTM-001",
        "nombre": "EJEMPLO TORNILLO M6",
        "descripcion": "TORNILLO HEXAGONAL M6X20 (BORRAR ESTA FILA DE EJEMPLO)",
        "categoria": "MECANIZADO",
        "padre_sku": "",
        "stock_actual": 100,
        "unidad_medida": "UND",
        "stock_minimo": 10,
        "precio_unitario": 0.50
    }]
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        pd.DataFrame(data).to_excel(writer, index=False, sheet_name="Plantilla")
    output.seek(0)
    return StreamingResponse(
        output,
        headers={'Content-Disposition': 'attachment; filename="plantilla_carga_masiva.xlsx"'},
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# --- CARGA Y EXPORTACIÓN MASIVA ---
@app.post("/productos/cargar-masivo")
async def cargar_stock_masivo(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db), user: Usuario = Depends(verificar_roles([NombreRol.ADMIN, NombreRol.COORDINADOR]))):
    contents = await file.read()
    buffer = io.BytesIO(contents)

    try:
        df = pd.read_csv(buffer) if file.filename.endswith(".csv") else pd.read_excel(buffer)
    except Exception:
        raise HTTPException(status_code=400, detail="No se pudo leer el archivo. Verifica que sea un CSV o Excel válido.")

    # Columnas obligatorias: si falta alguna, se avisa antes de procesar
    # nada, en vez de que explote a mitad de la carga con un KeyError.
    columnas_requeridas = {"codigo_sku", "nombre", "stock_actual", "stock_minimo", "precio_unitario"}
    columnas_presentes = set(df.columns)
    faltantes = columnas_requeridas - columnas_presentes
    if faltantes:
        raise HTTPException(
            status_code=400,
            detail=f"Faltan columnas obligatorias en el archivo: {', '.join(sorted(faltantes))}"
        )

    filas_con_error = []

    for idx, row in df.iterrows():
        numero_fila = idx + 2  # +2 porque idx empieza en 0 y la fila 1 es el encabezado
        try:
            sku = str(row["codigo_sku"]).strip().upper()
            if not sku or sku == "NAN":
                filas_con_error.append(f"Fila {numero_fila}: código SKU vacío")
                continue

            cat = str(row.get("categoria", "GENERAL")).strip().upper()
            if not cat or cat == "NAN":
                cat = "GENERAL"

            padre_raw = row.get("padre_sku")
            padre = str(padre_raw).strip().upper() if pd.notna(padre_raw) else None

            stock_actual = int(row["stock_actual"])
            stock_minimo = int(row["stock_minimo"])
            precio_unitario = float(row["precio_unitario"])
            nombre = str(row["nombre"]).strip().upper()

            prod = db.query(Producto).filter(Producto.codigo_sku == sku).first()

            if prod:
                prod.stock_actual += stock_actual
                prod.precio_unitario = precio_unitario
                prod.categoria = cat
                if padre:
                    prod.padre_sku = padre
            else:
                db.add(Producto(
                    codigo_sku=sku,
                    nombre=nombre,
                    descripcion=str(row.get("descripcion", "")).strip().upper(),
                    categoria=cat,
                    padre_sku=padre,
                    stock_actual=stock_actual,
                    unidad_medida=str(row.get("unidad_medida", "UND")).strip().upper(),
                    stock_minimo=stock_minimo,
                    precio_unitario=precio_unitario
                ))

        except (ValueError, KeyError, TypeError) as e:
            filas_con_error.append(f"Fila {numero_fila}: {str(e)}")
            continue

    db.commit()
    registrar_auditoria(db, user.id, TipoAccion.CARGA_MASIVA, "PRODUCTOS", request.client.host, f"CARGA MASIVA ARCHIVO: {file.filename}")

    resultado = {"mensaje": "Carga completada"}
    if filas_con_error:
        resultado["advertencias"] = filas_con_error
        resultado["mensaje"] = f"Carga completada con {len(filas_con_error)} fila(s) con errores (se omitieron)"

    return resultado


@app.get("/productos/exportar-excel")
def exportar_inventario_excel(db: Session = Depends(get_db), user: Usuario = Depends(verificar_roles([NombreRol.ADMIN, NombreRol.COORDINADOR]))):
    productos = db.query(Producto).all()
    data = [{
        "SKU": p.codigo_sku,
        "NOMBRE": p.nombre,
        "CATEGORIA": p.categoria,
        "PADRE / CONJUNTO": p.padre_sku or "-",
        "STOCK": p.stock_actual,
        "UNIDAD": p.unidad_medida,
        "STOCK MIN": p.stock_minimo,
        "PRECIO": p.precio_unitario
    } for p in productos]

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        pd.DataFrame(data).to_excel(writer, index=False, sheet_name="Inventario")
    output.seek(0)
    return StreamingResponse(
        output,
        headers={'Content-Disposition': 'attachment; filename="inventario.xlsx"'},
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@app.get("/auditoria/historial")
def obtener_historial_auditoria(db: Session = Depends(get_db), user: Usuario = Depends(verificar_roles([NombreRol.ADMIN, NombreRol.COORDINADOR]))):
    logs = db.query(AuditoriaLog).order_by(AuditoriaLog.timestamp.desc()).limit(100).all()
    return [
        {
            "id": l.id,
            "usuario": l.usuario.username if l.usuario else "SISTEMA",
            "accion": l.accion.value,
            "tabla": l.tabla_afectada,
            "ip_origen": l.ip_origen,
            "detalles": l.detalles,
            "timestamp": l.timestamp.isoformat()
        } for l in logs
    ]


@app.get("/app", response_class=HTMLResponse, include_in_schema=False)
def obtener_interfaz_usuario():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()