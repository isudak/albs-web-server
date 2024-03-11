# -*- mode:python; coding:utf-8; -*-
# author: Vyacheslav Potoropin <vpotoropin@almalinux.org>
# created: 2021-06-22
from sqlalchemy import MetaData, create_engine
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, scoped_session, sessionmaker
from sqlalchemy.pool import NullPool

from alws.config import settings

__all__ = ['Base', 'Session', 'SyncSession', 'PulpSession', 'engine']


DATABASE_URL = settings.database_url

engine = create_async_engine(DATABASE_URL, poolclass=NullPool, echo_pool=True)
sync_engine = create_engine(
    settings.sync_database_url, pool_pre_ping=True, pool_recycle=3600
)


class Base(AsyncAttrs, DeclarativeBase):
    __allow_unmapped__ = True
    metadata = MetaData()


sync_session_factory = sessionmaker(sync_engine, expire_on_commit=False)
Session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
SyncSession = scoped_session(sync_session_factory)


class PulpBase(AsyncAttrs, DeclarativeBase):
    __allow_unmapped__ = True


pulp_engine = create_engine(
    settings.pulp_database_url, pool_pre_ping=True, pool_recycle=3600
)
pulp_session_factory = sessionmaker(pulp_engine, expire_on_commit=False)
PulpSession = scoped_session(pulp_session_factory)
