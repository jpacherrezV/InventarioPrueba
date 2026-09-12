from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Ruta de conexión a la base de datos SQLite.
# En desarrollo esto está bien como constante; si en algún momento
# el proyecto pasa a otro entorno (staging/producción), conviene
# leerlo de una variable de entorno en vez de tenerlo fijo acá.
SQLALCHEMY_DATABASE_URL = "sqlite:///./inventario.db"

# Engine de SQLAlchemy.
# check_same_thread=False es necesario porque SQLite por defecto solo
# permite que el hilo que abrió la conexión la use; FastAPI atiende
# requests en distintos hilos (via threadpool), así que sin este flag
# tirarías errores intermitentes de "SQLite objects created in a thread...".
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Fábrica de sesiones. autocommit=False y autoflush=False son los valores
# recomendados para trabajar con FastAPI: vos controlás explícitamente
# cuándo se hace commit() en cada endpoint, en vez de que SQLAlchemy
# lo haga por su cuenta en momentos inesperados.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Instancia central de Base: todos los modelos en models.py heredan de acá.
Base = declarative_base()


def get_db():
    """
    Dependencia de FastAPI para inyectar una sesión de base de datos
    en cada endpoint. El 'yield' entrega la sesión, y pase lo que pase
    (incluso si el endpoint lanza una excepción), el 'finally' garantiza
    que la conexión se cierre y no quede colgada.

    Esta es la ÚNICA definición de get_db en todo el proyecto —
    auth.py tenía una copia idéntica que no se usaba en ningún lado
    y se eliminó para evitar confusión sobre cuál es la real.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()