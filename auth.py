import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, ExpiredSignatureError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from database import get_db
from models import Usuario, NombreRol

# La clave secreta ahora se lee de una variable de entorno.
# Si no está definida, el servidor no arranca — esto evita el riesgo
# de que alguien despliegue el sistema sin darse cuenta de que sigue
# usando la clave de ejemplo hardcodeada en el código.
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "La variable de entorno SECRET_KEY no está definida. "
        "Configúrala antes de iniciar el servidor (ver archivo .env.example)."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 horas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    # datetime.now(timezone.utc) en vez de datetime.utcnow():
    # utcnow() está deprecado desde Python 3.12 y devuelve un datetime
    # "naive" (sin timezone), lo cual puede generar bugs sutiles de
    # comparación de fechas más adelante. now(timezone.utc) es explícito.
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_usuario_actual(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Usuario:
    exception_invalido = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales de autenticación no válidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    exception_expirado = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Tu sesión expiró, por favor inicia sesión de nuevo",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise exception_invalido
    except ExpiredSignatureError:
        # Se separa este caso de JWTError porque el frontend puede
        # reaccionar distinto: por ejemplo, redirigir directo al login
        # con un mensaje de "sesión expirada" en vez de "credenciales inválidas".
        raise exception_expirado
    except JWTError:
        raise exception_invalido

    usuario = db.query(Usuario).filter(Usuario.username == username).first()

    # usuario.activo ya existe en el modelo (se agregó la columna en models.py).
    # Este chequeo permite desactivar una cuenta sin borrarla —
    # por ejemplo, si un operario deja la empresa pero querés
    # conservar su historial de movimientos.
    if usuario is None or not usuario.activo:
        raise exception_invalido

    return usuario


def verificar_roles(roles_permitidos: list[NombreRol]):
    def wrapper(usuario: Usuario = Depends(get_usuario_actual)):
        # Chequeo defensivo: si por algún motivo el usuario quedó sin
        # rol asignado (rol_id apuntando a un registro borrado, por ejemplo),
        # usuario.rol sería None y usuario.rol.nombre tiraría AttributeError
        # -- el mismo tipo de error 500 que ya vimos con 'activo'.
        # Mejor devolver un 403 claro que un crash.
        if usuario.rol is None or usuario.rol.nombre not in roles_permitidos:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes los permisos necesarios para realizar esta acción"
            )
        return usuario
    return wrapper