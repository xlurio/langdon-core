from __future__ import annotations

import contextlib
import tomllib
from typing import TYPE_CHECKING

import sqlalchemy
from sqlalchemy import orm

from langdon_core.models import SqlAlchemyModel

if TYPE_CHECKING:
    from types import TracebackType

    from langdon_core.langdon_core_t import ConfigurationKeyT


class LangdonManager(contextlib.AbstractContextManager):
    def __init__(self) -> None:
        with open("pyproject.toml", "rb") as pyproject_file:
            self.__config = tomllib.load(pyproject_file)["tool"]["langdon"]

        db_path = self.__config["database"]
        self.__engine = sqlalchemy.create_engine(
            f"sqlite:///{db_path}",
        )

    def __enter__(self) -> LangdonManager:
        SqlAlchemyModel.metadata.create_all(self.__engine, checkfirst=True)
        self.__session = orm.Session(self.__engine)

        return self

    @property
    def session(self) -> orm.Session:
        return self.__session

    @property
    def config(self) -> dict[ConfigurationKeyT, str]:
        return self.__config

    def __exit__(
        self,
        exc_type: type[Exception] | None,
        exc_value: Exception | None,
        traceback: TracebackType,
    ) -> None:
        self.__session.rollback()
        self.__session.close()

        if exc_type is not None:
            raise exc_value.with_traceback(traceback)
