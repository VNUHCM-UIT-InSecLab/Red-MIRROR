from contextlib import contextmanager
from functools import wraps

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base

from config.config import Configs


def _resolve_db_url() -> str:
    mysql = Configs.db_config.mysql
    required = [str(mysql.get("host", "")).strip(), str(mysql.get("user", "")).strip(), str(mysql.get("database", "")).strip()]
    if all(required):
        return (
            f"mysql+pymysql://{mysql['user']}:{mysql['password']}@"
            f"{mysql['host']}:{mysql['port']}/{mysql['database']}"
        )

    sqlite_dir = Configs.PENTEST_ROOT / "data"
    sqlite_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{(sqlite_dir / 'vulnbot.db').resolve()}"


db_url = _resolve_db_url()

engine = create_engine(db_url)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base: DeclarativeMeta = declarative_base()

@contextmanager
def session_scope() -> Session:
    """上下文管理器用于自动获取 Session, 避免错误"""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()


def with_session(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        with session_scope() as session:
            try:
                result = f(session, *args, **kwargs)
                session.commit()
                return result
            except:
                session.rollback()
                raise

    return wrapper


def create_tables():
    # Import model modules so SQLAlchemy metadata is populated before create_all.
    from db.models import conversation_model, message_model, plan_model, session_model, task_model  # noqa: F401

    Base.metadata.create_all(bind=engine)
