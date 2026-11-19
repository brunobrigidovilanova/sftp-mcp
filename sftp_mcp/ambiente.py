"""Ambiente (prod, hml, dev) deduzido do usuario SFTP do TCloud."""

from __future__ import annotations

import re

AMBIENTE_PADRAO = "dev"
_DEDUCAO_AMBIENTE = (
    ("prod", re.compile(r"(^|[_-])(prod|production|producao)($|[_-])", re.IGNORECASE)),
    ("hml", re.compile(r"(^|[_-])(hml|homolog|homologacao|staging|stage|test|teste|qa)($|[_-])", re.IGNORECASE)),
    ("dev", re.compile(r"(^|[_-])(dev|development|desenvolvimento)($|[_-])", re.IGNORECASE)),
)


def ambiente_no_texto(texto: str) -> str | None:
    for ambiente, padrao in _DEDUCAO_AMBIENTE:
        if padrao.search(texto):
            return ambiente
    return None


def deduzir_ambiente(usuario: str) -> str:
    """Le o sufixo do usuario do TCloud (ftp_XXXXXX_development). Sem sufixo conhecido, usa o padrao."""
    return ambiente_no_texto(usuario) or AMBIENTE_PADRAO
