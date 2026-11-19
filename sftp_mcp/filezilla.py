"""Conexoes SFTP salvas no FileZilla, relidas a cada uso.

Fontes: Gerenciador de Sites (sitemanager.xml), que tem prioridade, e servidores recentes
(recentservers.xml). A chave do servidor e a que o usuario aceitou no FileZilla
(hostkeys.xml). A senha so e decodificada na hora de conectar e nunca sai deste processo.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import re
import struct
import sys
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from .ambiente import AMBIENTE_PADRAO, ambiente_no_texto

_PROTOCOLO_SFTP = "1"
# Logontype do FileZilla: 1 senha salva, 2 pedir senha, 3 interativo, 5 arquivo de chave.
_LOGON_SENHA = {"1", "2", "3"}
_LOGON_CHAVE = "5"


class ErroFileZilla(Exception):
    pass


@dataclass(frozen=True)
class Site:
    nome: str
    host: str
    porta: int
    usuario: str
    host_key: str
    autenticacao: str
    chave_privada: str
    ambiente: str
    fonte: str


@dataclass(frozen=True)
class Ignorado:
    nome: str
    motivo: str


def pasta() -> Path:
    if os.environ.get("FILEZILLA_HOME"):
        return Path(os.environ["FILEZILLA_HOME"])
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "FileZilla"
    return Path.home() / ".config" / "filezilla"


def _ler_xml(nome: str) -> ET.Element | None:
    arquivo = pasta() / nome
    if not arquivo.is_file():
        return None
    try:
        return ET.parse(arquivo).getroot()
    except (ET.ParseError, OSError) as e:
        # O FileZilla regrava esses arquivos enquanto esta aberto: leitura no meio da gravacao falha.
        raise ErroFileZilla(f"Nao leu {arquivo}: {e}. Tente de novo em alguns segundos.") from e


def _entradas():
    """(fonte, elemento Server) do Gerenciador de Sites e depois dos recentes."""
    for arquivo, secao, fonte in (
        ("sitemanager.xml", "Servers", "gerenciador de sites"),
        ("recentservers.xml", "RecentServers", "recentes"),
    ):
        raiz = _ler_xml(arquivo)
        bloco = raiz.find(secao) if raiz is not None else None
        if bloco is not None:
            for servidor in bloco.iter("Server"):
                yield fonte, servidor


def _texto(elemento: ET.Element, tag: str) -> str:
    return (elemento.findtext(tag) or "").strip()


def _identidade(servidor: ET.Element) -> tuple[str, int | None, str]:
    porta = _texto(servidor, "Port") or "22"
    return _texto(servidor, "Host").lower(), int(porta) if porta.isdigit() else None, _texto(servidor, "User")


def chave_openssh(blob: str | None) -> str:
    """O FileZilla grava so o blob SSH em base64; o OpenSSH quer o algoritmo na frente."""
    texto = (blob or "").strip()
    try:
        dados = base64.b64decode(texto, validate=True)
        (tamanho,) = struct.unpack(">I", dados[:4])
        chave = f"{dados[4:4 + tamanho].decode('ascii')} {texto}"
        asyncssh.import_public_key(chave)
    except (binascii.Error, struct.error, UnicodeDecodeError, ValueError, asyncssh.KeyImportError):
        return ""
    return chave


def _chaves_aceitas() -> dict[tuple[str, int], str]:
    raiz = _ler_xml("hostkeys.xml")
    chaves: dict[tuple[str, int], str] = {}
    if raiz is None:
        return chaves
    for servidor in raiz.iter("Server"):
        host = (servidor.get("Host") or "").strip().lower()
        porta = (servidor.get("Port") or "").strip()
        if not host or not porta.isdigit():
            continue
        for elemento in servidor.findall("Hostkey"):
            chave = chave_openssh(elemento.text)
            if chave:
                chaves[(host, int(porta))] = chave
    return chaves


def _senha_salva(servidor: ET.Element) -> str | None:
    elemento = servidor.find("Pass")
    texto = (elemento.text or "").strip() if elemento is not None else ""
    if not texto:
        return None
    codificacao = elemento.get("encoding", "")
    if codificacao == "":
        return texto
    # "crypt" e a senha mestra do FileZilla: sem ela nao ha como abrir.
    if codificacao != "base64":
        return None
    try:
        return base64.b64decode(texto, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None


def _slug(texto: str) -> str:
    ascii_ = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "-", ascii_.lower()).strip("-")[:63].strip("-")


def _nome_recente(host: str, ambiente: str) -> str:
    try:
        ipaddress.ip_address(host)
        base = host
    except ValueError:
        base = host.split(".")[0]
    return _slug(f"{base}-{ambiente}")


def sites() -> tuple[list[Site], list[Ignorado]]:
    """Conexoes SFTP utilizaveis e as que ficaram de fora, com o motivo."""
    chaves = _chaves_aceitas()
    validos: list[Site] = []
    ignorados: list[Ignorado] = []
    vistos: set[tuple] = set()
    for fonte, servidor in _entradas():
        host, porta, usuario = _identidade(servidor)
        host = _texto(servidor, "Host")
        nome_site = _slug(_texto(servidor, "Name")) if fonte != "recentes" else ""
        # Usuario sem sufixo do TCloud: o nome do site ("Cliente Producao") ainda diz o ambiente.
        ambiente = ambiente_no_texto(usuario) or ambiente_no_texto(nome_site) or AMBIENTE_PADRAO
        nome = nome_site or _nome_recente(host, ambiente)
        if not host or not usuario or porta is None:
            ignorados.append(Ignorado(nome or "(sem nome)", f"conexao do FileZilla ({fonte}) sem host, porta ou usuario"))
            continue
        if (_texto(servidor, "Protocol") or "0") != _PROTOCOLO_SFTP:
            ignorados.append(Ignorado(nome, f"{host}:{porta} nao e SFTP; o sftp-mcp so fala SFTP"))
            continue
        identidade = (host.lower(), porta, usuario)
        if identidade in vistos:
            continue
        vistos.add(identidade)
        logon = _texto(servidor, "Logontype")
        chave_privada = ""
        if logon in _LOGON_SENHA:
            autenticacao = "senha"
        elif logon == _LOGON_CHAVE:
            autenticacao = "chave"
            chave_privada = _texto(servidor, "Keyfile")
            if chave_privada.lower().endswith(".ppk"):
                ignorados.append(Ignorado(nome, "chave .ppk nao e suportada; exporte em formato OpenSSH no PuTTYgen"))
                continue
        else:
            ignorados.append(Ignorado(nome, f"tipo de logon {logon or '?'} do FileZilla nao suportado (anonimo ou conta)"))
            continue
        host_key = chaves.get((host.lower(), porta), "")
        if not host_key:
            ignorados.append(Ignorado(
                nome, f"o FileZilla nao tem chave aceita para {host}:{porta}: conecte uma vez por ele e aceite a chave",
            ))
            continue
        validos.append(Site(nome, host, porta, usuario, host_key, autenticacao, chave_privada, ambiente, fonte))
    # Nome repetido tira todas as conexoes com ele: o nome nao pode passar de um servidor a outro.
    repetidos = {n for n in (s.nome for s in validos) if sum(1 for s in validos if s.nome == n) > 1}
    for nome in sorted(repetidos):
        ignorados.append(Ignorado(nome, "nome repetido em mais de uma conexao do FileZilla; renomeie os sites"))
    return [s for s in validos if s.nome not in repetidos], ignorados


def identidade(host: str, porta: int, usuario: str) -> str:
    return f"{usuario}@{host.lower()}:{porta}"


def senha(host: str, porta: int, usuario: str) -> str | None:
    """Senha salva no FileZilla para a conexao, lida do disco agora. Senha mestra devolve None."""
    procurada = (host.lower(), porta, usuario)
    for _fonte, servidor in _entradas():
        if _identidade(servidor) == procurada:
            valor = _senha_salva(servidor)
            if valor:
                return valor
    return None
