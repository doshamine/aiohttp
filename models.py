import os
from datetime import datetime
from sqlalchemy import Integer, String, DateTime, func, ForeignKey, insert
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from auth import hash_password

POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "***")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "db")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "netology_advertisements")

PG_DSN = (
    f"postgresql+asyncpg://"
    f"{POSTGRES_USER}:{POSTGRES_PASSWORD}@"
    f"{POSTGRES_HOST}:{POSTGRES_PORT}/"
    f"{POSTGRES_DB}"
)

engine = create_async_engine(PG_DSN)
Session = async_sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase, AsyncAttrs):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String, nullable=False)

    @property
    def dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "password": self.password
        }

    @property
    def id_dict(self):
        return {
            "id": self.id
        }


class Advertisement(Base):
    __tablename__ = "advertisement"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    header: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))

    @property
    def dict(self):
        return {
            "id": self.id,
            "header": self.header,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "user": self.user_id
        }

    @property
    def id_dict(self):
        return {
            "id": self.id
        }


async def init_orm():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

        stmt = insert(User).values({'email': '<EMAIL1>', 'password': hash_password('<PASSWORD1>')})
        await conn.execute(stmt)
        stmt = insert(User).values({'email': '<EMAIL2>', 'password': hash_password('<PASSWORD2>')})
        await conn.execute(stmt)
        await conn.commit()


async def close_orm():
    await engine.dispose()