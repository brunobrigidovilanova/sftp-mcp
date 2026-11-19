"""Cadastro de perfil proprio (fora do FileZilla) a partir dos dados que o TCloud mostra.

O CLI (sftp-mcp-setup adicionar) usa estas funcoes; a senha e digitada no terminal e nao
passa pelo servidor MCP nem pelo modelo.
"""

from __future__ import annotations

import contextlib
import re
from pathlib import Path

from . import armazenamento, credenciais
from .armazenamento import raiz_git
from .conexao import GerenciadorConexoes
from .config import Perfil, carregar_perfis, salvar_perfil
from .operacoes import ErroOperacao


def separar_url(texto: str) -> tuple[str, int | None, str]:
    """Aceita 'host', 'host:porta', 'usuario@host' e 'sftp://host:porta/rota'."""
    valor = re.sub(r"^[a-z][a-z0-9+.-]*://", "", texto.strip(), flags=re.IGNORECASE)
    autoridade, barra, rota = valor.partition("/")
    host, _, porta = autoridade.rsplit("@", 1)[-1].partition(":")
    rota = ("/" + rota).rstrip("/") if barra else ""
    return host, int(porta) if porta.isdigit() else None, rota


def erro_repositorio(texto: str) -> str | None:
    if not texto:
        return None
    pasta = Path(texto).expanduser()
    if not pasta.is_dir():
        return f"Pasta nao existe: {pasta}"
    if raiz_git(pasta) is None:
        return f"{pasta} nao e repositorio git."
    return None


def chave_conhecida(chave: str) -> bool:
    """Chave ja aceita em outro perfil: no TCloud varios ambientes ficam atras do mesmo gateway."""
    return any(p.host_key == chave for p in carregar_perfis().values())


async def registrar(perfil: Perfil, segredo: str, repositorio: str = "") -> dict:
    """Testa o login com o segredo so em memoria e grava por ultimo: falha nao deixa nada para tras."""
    perfil.validar()
    gerenciador = GerenciadorConexoes()
    try:
        async with gerenciador.usar(perfil, segredo) as sftp:
            await sftp.realpath(".")
    finally:
        await gerenciador.fechar_todas()
    aviso = None
    if repositorio:
        raiz = raiz_git(Path(repositorio).expanduser())
        if raiz is None:
            raise ErroOperacao(f"{repositorio} nao e repositorio git.")
        perfil.repositorio = str(raiz)
        armazenamento.pasta_perfil(perfil)
        aviso = armazenamento.aviso_git(raiz, perfil.nome)
    # A confirmacao da chave no terminal nao tem prazo: o nome pode ter sido gravado nesse meio tempo.
    if perfil.nome in carregar_perfis():
        raise ErroOperacao(f"O perfil {perfil.nome} ja existe.")
    if segredo:
        credenciais.gravar(perfil.nome, "senha" if perfil.autenticacao == "senha" else "passphrase", segredo)
    try:
        salvar_perfil(perfil)
    except BaseException:
        credenciais.remover(perfil.nome)
        raise
    if perfil.repositorio:
        with contextlib.suppress(OSError):
            armazenamento.auditar(perfil, "cadastrar", "ok", host=perfil.host, repositorio=perfil.repositorio)
    return {
        "status": "cadastrado",
        "perfil": perfil.nome,
        "host": perfil.host,
        "porta": perfil.porta,
        "ambiente": perfil.ambiente,
        "pasta_inicial": perfil.pasta_inicial,
        "repositorio": perfil.repositorio,
        "aviso": aviso,
    }
