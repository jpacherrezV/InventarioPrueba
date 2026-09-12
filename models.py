import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey, DateTime, Enum as SQLEnum
from sqlalchemy.orm import relationship
from database import Base


class NombreRol(str, enum.Enum):
    ADMIN = "ADMIN"
    COORDINADOR = "COORDINADOR"
    OPERARIO = "OPERARIO"


class TipoAccion(str, enum.Enum):
    CREAR = "CREAR"
    MODIFICAR = "MODIFICAR"
    ELIMINAR = "ELIMINAR"
    INGRESO_STOCK = "INGRESO_STOCK"
    SALIDA_STOCK = "SALIDA_STOCK"
    AJUSTE_STOCK = "AJUSTE_STOCK"   # <-- NUEVO: faltaba un tercer valor para el caso AJUSTE
    CARGA_MASIVA = "CARGA_MASIVA"
    LOGIN = "LOGIN"


class TipoMovimiento(str, enum.Enum):
    INGRESO = "INGRESO"
    SALIDA = "SALIDA"
    AJUSTE = "AJUSTE"


class Rol(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(SQLEnum(NombreRol), unique=True, nullable=False)
    usuarios = relationship("Usuario", back_populates="rol")


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    rol_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    activo = Column(Boolean, default=True, nullable=False)  # <-- NUEVO: era la causa del AttributeError

    rol = relationship("Rol", back_populates="usuarios")
    movimientos = relationship("MovimientoInventario", back_populates="usuario")
    logs_auditoria = relationship("AuditoriaLog", back_populates="usuario")


class Producto(Base):
    __tablename__ = "productos"

    id = Column(Integer, primary_key=True, index=True)
    codigo_sku = Column(String, unique=True, index=True, nullable=False)
    nombre = Column(String, nullable=False)
    descripcion = Column(String, nullable=True)
    categoria = Column(String, default="GENERAL", nullable=False)
    padre_sku = Column(String, nullable=True)
    stock_actual = Column(Integer, default=0, nullable=False)
    unidad_medida = Column(String, default="UND", nullable=False)
    stock_minimo = Column(Integer, default=5, nullable=False)
    precio_unitario = Column(Float, default=0.0, nullable=False)

    movimientos = relationship("MovimientoInventario", back_populates="producto", cascade="all, delete-orphan")


class MovimientoInventario(Base):
    __tablename__ = "movimientos_inventario"

    id = Column(Integer, primary_key=True, index=True)
    producto_id = Column(Integer, ForeignKey("productos.id"), nullable=False)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=False)
    tipo = Column(SQLEnum(TipoMovimiento), nullable=False)
    cantidad = Column(Integer, nullable=False)
    observacion = Column(String, nullable=True)
    fecha_registro = Column(DateTime, default=datetime.utcnow, nullable=False)

    producto = relationship("Producto", back_populates="movimientos")
    usuario = relationship("Usuario", back_populates="movimientos")


class AuditoriaLog(Base):
    __tablename__ = "auditoria_logs"

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)
    accion = Column(SQLEnum(TipoAccion), nullable=False)
    tabla_afectada = Column(String, nullable=False)
    ip_origen = Column(String, nullable=False)
    detalles = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    usuario = relationship("Usuario", back_populates="logs_auditoria")