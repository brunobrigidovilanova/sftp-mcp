"""Operacoes SFTP expostas pelas tools.

Toda operacao trabalha sobre o caminho remoto ja resolvido pelo servidor (realpath),
e a checagem de raiz usa esse mesmo caminho. Assim symlink e '..' nao escapam da raiz.
"""

from __future__ import annotations

import codecs
import contextlib
import datetime as dt
import fnmatch
import hashlib
import json
import posixpath
import re
import secrets
import stat
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

from . import armazenamento, config, nomes
from .armazenamento import ErroRepositorio
from .conexao import ErroConexao, GerenciadorConexoes, segredo_salvo
from .config import ErroConfig, Perfil

_BLOCO = 65_536
_AMOSTRA_BINARIO = 8_192
# Barra invertida e separador para servidor SFTP sobre Windows: "a\..\..\x" escaparia
# da raiz sem passar pelo realpath. Caractere invisivel mascararia o destino no prompt.
_PROIBIDOS = re.compile("[\\\\\x00-\x1f\x7f​-‏‪-‮⁠-⁤⁦-⁩﻿]")


# Itens devolvidos por listar/buscar quando o agente nao pede outro limite: pasta do Protheus
# (system, spool) passa de mil itens e despejaria centenas de KB no contexto.
LIMITE_PADRAO = 200
ORDENS = ("nome", "modificado", "tamanho")
# Busca e varredura de lote param aqui e devolvem o que acharam.
TEMPO_MAX_VARREDURA = 60
LOTE_MAX_ARQUIVOS = 500
LOTE_MAX_BYTES = 500_000_000
LOTE_MAX_ENVIO = 100


class ErroOperacao(Exception):
    pass


ERROS_ESPERADOS = (ErroOperacao, ErroConfig, ErroConexao, ErroRepositorio)


def _validar_caminho(caminho: str) -> str:
    if not caminho:
        raise ErroOperacao("Caminho remoto vazio.")
    if _PROIBIDOS.search(nomes.sem_escapes(caminho)):
        raise ErroOperacao(
            "Caminho remoto com barra invertida ou caractere de controle/invisivel. "
            "Use '/' como separador, inclusive em servidor Windows. Byte que nao e UTF-8 vai como \\xHH."
        )
    return posixpath.normpath(nomes.ler(caminho))


def _dentro(caminho: str, raizes: list[str], *, estrito: bool = False) -> bool:
    for raiz in raizes:
        if caminho == raiz:
            if not estrito:
                return True
        elif caminho.startswith(raiz.rstrip("/") + "/"):
            return True
    return False


def _tipo(attrs: asyncssh.SFTPAttrs) -> str:
    modo = attrs.permissions
    if modo is None:
        return "outro"
    if stat.S_ISDIR(modo):
        return "pasta"
    if stat.S_ISREG(modo):
        return "arquivo"
    if stat.S_ISLNK(modo):
        return "link"
    return "outro"


def _data(epoch: int | None) -> str | None:
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="seconds")


def _descrever(caminho: str, attrs: asyncssh.SFTPAttrs) -> dict:
    return {
        "caminho": caminho,
        "tipo": _tipo(attrs),
        "tamanho": attrs.size,
        "modificado": _data(attrs.mtime),
        "permissoes": stat.filemode(attrs.permissions) if attrs.permissions is not None else None,
    }


def _sem_utf8_incompleto(dados: bytes) -> bytes:
    """Remove do fim um caractere UTF-8 cortado pelo limite de leitura."""
    for recuo in range(1, min(4, len(dados)) + 1):
        byte = dados[-recuo]
        if byte & 0xC0 != 0x80:  # inicio de caractere
            tamanho = 2 if byte >= 0xC0 else 1
            tamanho = 3 if byte >= 0xE0 else tamanho
            tamanho = 4 if byte >= 0xF0 else tamanho
            return dados[:-recuo] if tamanho > recuo else dados
    return dados


def _decodificar(dados: bytes, encoding: str | None, cortado: bool = False) -> tuple[str, str]:
    if encoding:
        return dados.decode(encoding, errors="replace"), encoding
    candidatos = [dados, _sem_utf8_incompleto(dados)] if cortado else [dados]
    for candidato in candidatos:
        try:
            return candidato.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            pass
    return dados.decode("cp1252", errors="replace"), "cp1252"


def _validar_encoding(encoding: str | None) -> None:
    if encoding:
        try:
            codecs.lookup(encoding)
        except LookupError:
            raise ErroOperacao(f"Encoding desconhecido: {encoding}") from None


def _sha256(arquivo: Path) -> str:
    h = hashlib.sha256()
    with arquivo.open("rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def _separar_linhas(dados: bytes) -> list[bytes]:
    """Quebra so em \\n, como o sftp_ler, mantendo o fim de linha."""
    partes = [p + b"\n" for p in dados.split(b"\n")]
    ultima = partes.pop()[:-1]
    if ultima:
        partes.append(ultima)
    return partes


def _mensagem_sftp(e: asyncssh.SFTPError, caminho: str) -> str:
    if isinstance(e, asyncssh.SFTPNoSuchFile):
        return f"Nao existe no servidor: {caminho}"
    if isinstance(e, asyncssh.SFTPPermissionDenied):
        return f"Sem permissao no servidor: {caminho}"
    return f"Erro SFTP em {caminho}: {e.reason}"


def _conferir_ordem_e_limite(ordenar: str, limite: int | None) -> None:
    if ordenar not in ORDENS:
        raise ErroOperacao(f"ordenar deve ser {', '.join(ORDENS)}.")
    if limite is not None and limite < 1:
        raise ErroOperacao("limite comeca em 1.")


def _ordenados(itens: list[tuple[str, asyncssh.SFTPAttrs]], ordenar: str, *, pastas_primeiro: bool) -> list:
    """modificado e tamanho: maior primeiro (o log mais recente, o arquivo maior)."""
    if ordenar == "modificado":
        return sorted(itens, key=lambda i: i[1].mtime or 0, reverse=True)
    if ordenar == "tamanho":
        return sorted(itens, key=lambda i: i[1].size or 0, reverse=True)
    if pastas_primeiro:
        return sorted(itens, key=lambda i: (_tipo(i[1]) != "pasta", i[0].lower()))
    return sorted(itens, key=lambda i: i[0].lower())


@dataclass
class _Varredura:
    achados: list = field(default_factory=list)
    sem_acesso: list = field(default_factory=list)
    com_erro: list = field(default_factory=list)
    truncado: bool = False
    interrompido: bool = False


async def _varrer(sftp, raiz: str, profundidade: int, aceitar, max_achados: int) -> _Varredura:
    """Desce em largura ate a profundidade, sem seguir link de pasta (evita laco e saida da raiz)."""
    v = _Varredura()
    prazo = time.monotonic() + TEMPO_MAX_VARREDURA
    fila = deque([(raiz, 1)])
    while fila and not v.truncado:
        if time.monotonic() > prazo:
            v.interrompido = True
            break
        pasta, nivel = fila.popleft()
        try:
            itens = await sftp.readdir(pasta)
        except (asyncssh.SFTPNoSuchFile, asyncssh.SFTPPermissionDenied):
            v.sem_acesso.append(pasta)
            continue
        except (asyncssh.SFTPConnectionLost, asyncssh.SFTPNoConnection):
            raise
        except asyncssh.SFTPError as e:
            v.com_erro.append({"pasta": pasta, "erro": str(e) or type(e).__name__})
            continue
        for item in itens:
            if item.filename in (".", ".."):
                continue
            completo = posixpath.join(pasta, item.filename)
            tipo_item = _tipo(item.attrs)
            if tipo_item == "pasta" and nivel < profundidade:
                fila.append((completo, nivel + 1))
            if not aceitar(item.filename, tipo_item):
                continue
            if len(v.achados) >= max_achados:
                v.truncado = True
                break
            v.achados.append((completo, item.attrs))
    return v


async def _baixar_um(sftp, remoto: str, destino: Path) -> tuple[int, str]:
    try:
        await sftp.get(remoto, str(destino))
    except BaseException:
        destino.unlink(missing_ok=True)  # nao deixa download pela metade
        raise
    return destino.stat().st_size, _sha256(destino)


class _DestinoApagado(ErroOperacao):
    """A troca apagou o destino e nao conseguiu por o novo no lugar: o temporario nao pode sumir."""


async def _substituir(sftp, temporario: str, real: str, backup) -> None:
    try:
        await sftp.posix_rename(temporario, real)
    except asyncssh.SFTPOpUnsupported:
        # Servidor sem posix-rename: a versao anterior ja esta em backups/.
        await sftp.remove(real)
        try:
            await sftp.rename(temporario, real)
        except asyncssh.SFTPError as e:
            raise _DestinoApagado(
                f"{real} foi apagado para a troca, mas renomear falhou ({e}). O conteudo novo ficou em "
                f"{temporario} e a versao anterior em {backup}."
            ) from None


def _arquivo_local(texto: str) -> Path:
    origem = Path(texto).expanduser()
    if not origem.is_file():
        raise ErroOperacao(f"Arquivo local nao existe ou nao e arquivo: {origem}")
    return origem


def _conferir_destino(real: str, atual: asyncssh.SFTPAttrs | None, sobrescrever: bool) -> None:
    if atual is None:
        return
    if _tipo(atual) != "arquivo":
        raise ErroOperacao(f"{real} existe e nao e arquivo regular ({_tipo(atual)}). Nada enviado.")
    if not sobrescrever:
        raise ErroOperacao(f"{real} ja existe. Para substituir, chame de novo com sobrescrever=true.")


class Operacoes:
    def __init__(self, gerenciador: GerenciadorConexoes) -> None:
        self._gerenciador = gerenciador

    # ------------------------------------------------------------------
    # Apoio

    def _perfil(self, nome_perfil: str, *, exige_repositorio: bool = False) -> Perfil:
        perfil = config.obter_perfil(nome_perfil)
        # Download, backup e escrita ficam no repositorio do cliente: conferido antes de conectar.
        if exige_repositorio:
            armazenamento.pasta_perfil(perfil)
        return perfil

    async def _auditado(self, perfil: Perfil, operacao: str, dados: dict, executar):
        try:
            async with self._gerenciador.usar(perfil) as sftp:
                resultado = await executar(sftp)
        except ERROS_ESPERADOS as e:
            armazenamento.auditar(perfil, operacao, "erro", **{**dados, "erro": str(e)})
            raise
        except asyncssh.SFTPError as e:
            mensagem = _mensagem_sftp(e, dados.get("caminho", ""))
            armazenamento.auditar(perfil, operacao, "erro", **{**dados, "erro": mensagem})
            raise ErroOperacao(mensagem) from None
        except Exception as e:
            armazenamento.auditar(perfil, operacao, "erro", **{**dados, "erro": f"{type(e).__name__}: {e}"})
            raise
        armazenamento.auditar(perfil, operacao, "ok", **{**dados, **resultado.pop("_auditoria", {})})
        return resultado

    async def _realpath(self, sftp: asyncssh.SFTPClient, caminho: str) -> str:
        try:
            return await sftp.realpath(caminho)
        except asyncssh.SFTPError as e:
            raise ErroOperacao(_mensagem_sftp(e, caminho)) from None

    async def _resolver_existente(self, sftp, caminho: str) -> str:
        return await self._realpath(sftp, _validar_caminho(caminho))

    async def _resolver_novo(self, sftp, caminho: str) -> str:
        """Caminho de algo que pode nao existir: resolve a pasta mae e anexa o nome."""
        normalizado = _validar_caminho(caminho)
        nome = posixpath.basename(normalizado)
        if nome in ("", ".", ".."):
            raise ErroOperacao(f"Caminho sem nome de arquivo ou pasta: {caminho}")
        mae = posixpath.dirname(normalizado) or "."
        return posixpath.join(await self._realpath(sftp, mae), nome)

    async def _resolver_com_pais(self, sftp, caminho: str) -> str:
        """Resolve o ancestral mais proximo que existe e anexa os segmentos que faltam."""
        normalizado = _validar_caminho(caminho)
        faltando: list[str] = []
        atual = normalizado
        while True:
            try:
                base = await sftp.realpath(atual)
                break
            except asyncssh.SFTPNoSuchFile:
                nome = posixpath.basename(atual)
                if nome in ("", ".", ".."):
                    raise ErroOperacao(f"Nao foi possivel resolver {caminho}") from None
                faltando.insert(0, nome)
                atual = posixpath.dirname(atual) or "."
            except asyncssh.SFTPError as e:
                raise ErroOperacao(_mensagem_sftp(e, atual)) from None
        return posixpath.join(base, *faltando) if faltando else base

    async def _raizes_reais(self, sftp, raizes: list[str]) -> list[str]:
        reais = []
        for raiz in raizes:
            try:
                reais.append(await sftp.realpath(raiz))
            except asyncssh.SFTPError:
                raise ErroOperacao(f"A raiz {raiz} do perfil nao existe no servidor.") from None
        return reais

    async def _checar_leitura(self, perfil: Perfil, sftp, caminho_real: str) -> None:
        if perfil.raizes_leitura and not _dentro(caminho_real, await self._raizes_reais(sftp, perfil.raizes_leitura)):
            raise ErroOperacao(
                f"{caminho_real} esta fora das raizes de leitura do perfil {perfil.nome}: "
                f"{', '.join(perfil.raizes_leitura)}"
            )

    async def _checar_escrita(self, perfil: Perfil, sftp, caminho_real: str, *, estrito: bool = False) -> None:
        """estrito recusa a propria raiz: mover a raiz mexe na pasta mae, fora dela."""
        # raizes_escrita e restricao opcional: quem autoriza a escrita e o prompt de aprovacao.
        if not perfil.raizes_escrita:
            return
        if not _dentro(caminho_real, await self._raizes_reais(sftp, perfil.raizes_escrita), estrito=estrito):
            raise ErroOperacao(
                f"{caminho_real} esta fora das raizes de escrita do perfil {perfil.nome}: "
                f"{', '.join(perfil.raizes_escrita)}"
            )

    async def _lstat(self, sftp, caminho: str) -> asyncssh.SFTPAttrs | None:
        try:
            return await sftp.lstat(caminho)
        except asyncssh.SFTPNoSuchFile:
            return None

    async def _stat_leitura(self, perfil, sftp, caminho: str) -> tuple[str, asyncssh.SFTPAttrs]:
        real = await self._resolver_existente(sftp, caminho)
        await self._checar_leitura(perfil, sftp, real)
        try:
            return real, await sftp.stat(real)
        except asyncssh.SFTPError as e:
            raise ErroOperacao(_mensagem_sftp(e, real)) from None

    async def _abrir_texto(self, perfil, sftp, caminho):
        real, attrs = await self._stat_leitura(perfil, sftp, caminho)
        if _tipo(attrs) != "arquivo":
            raise ErroOperacao(f"{real} nao e arquivo regular.")
        arquivo = await sftp.open(real, "rb")
        amostra = await arquivo.read(_AMOSTRA_BINARIO, 0)
        if b"\0" in amostra:
            await arquivo.close()
            return real, attrs, None
        return real, attrs, arquivo

    # ------------------------------------------------------------------
    # Leitura

    def perfis(self) -> list[dict]:
        lista = []
        perfis, ignorados = config.carregar_com_ignorados()
        for perfil in perfis.values():
            try:
                tem_segredo = bool(segredo_salvo(perfil))
            except ErroConexao:
                tem_segredo = False
            lista.append({
                "perfil": perfil.nome,
                "origem": perfil.origem,
                "host": perfil.host,
                "porta": perfil.porta,
                "usuario": perfil.usuario,
                "ambiente": perfil.ambiente,
                "tspace_cliente": perfil.tspace_cliente,
                "autenticacao": perfil.autenticacao,
                "segredo_cadastrado": tem_segredo,
                "repositorio": perfil.repositorio,
                "repositorio_existe": bool(perfil.repositorio) and Path(perfil.repositorio).is_dir(),
                "raizes_leitura": perfil.raizes_leitura,
                "raizes_escrita": perfil.raizes_escrita,
            })
        lista += [
            {"perfil": i["perfil"], "origem": i["origem"], "indisponivel": i["motivo"]} for i in ignorados
        ]
        return lista

    async def listar(
        self,
        nome_perfil: str,
        caminho: str = ".",
        padrao: str | None = None,
        ordenar: str = "nome",
        limite: int | None = None,
    ) -> dict:
        _conferir_ordem_e_limite(ordenar, limite)
        perfil = self._perfil(nome_perfil)
        maximo = min(limite or LIMITE_PADRAO, perfil.busca_max_resultados)

        async def executar(sftp):
            real, attrs = await self._stat_leitura(perfil, sftp, caminho)
            if _tipo(attrs) != "pasta":
                raise ErroOperacao(f"{real} nao e pasta. Use sftp_info ou sftp_ler.")
            itens = [
                (item.filename, item.attrs)
                for item in await sftp.readdir(real)
                if item.filename not in (".", "..")
                and (not padrao or fnmatch.fnmatch(item.filename.lower(), padrao.lower()))
            ]
            itens = _ordenados(itens, ordenar, pastas_primeiro=True)
            entradas = []
            for nome, item_attrs in itens[:maximo]:
                entrada = _descrever(nome, item_attrs)
                entrada["nome"] = entrada.pop("caminho")
                entradas.append(entrada)
            return {
                "caminho": real,
                "ordenado_por": ordenar,
                "total": len(itens),
                "entradas": entradas,
                "truncado": len(itens) > len(entradas),
                "_auditoria": {"itens": len(entradas)},
            }

        return await self._auditado(perfil, "listar", {"caminho": caminho}, executar)

    async def info(self, nome_perfil: str, caminho: str) -> dict:
        perfil = self._perfil(nome_perfil)

        async def executar(sftp):
            real, attrs = await self._stat_leitura(perfil, sftp, caminho)
            descricao = _descrever(real, attrs)
            descricao.update(uid=attrs.uid, gid=attrs.gid, acessado=_data(attrs.atime))
            return descricao

        return await self._auditado(perfil, "info", {"caminho": caminho}, executar)

    async def ler(
        self,
        nome_perfil: str,
        caminho: str,
        linha_inicial: int = 1,
        max_linhas: int | None = None,
        encoding: str | None = None,
    ) -> dict:
        _validar_encoding(encoding)
        if linha_inicial < 1 or (max_linhas is not None and max_linhas < 1):
            raise ErroOperacao("linha_inicial e max_linhas comecam em 1.")
        perfil = self._perfil(nome_perfil)

        async def executar(sftp):
            real, attrs, arquivo = await self._abrir_texto(perfil, sftp, caminho)
            if arquivo is None:
                return _binario(real, attrs)
            limite = perfil.max_leitura_bytes
            saida = bytearray()
            numero = 0
            devolvidas = 0
            truncado = False
            ha_mais = False
            try:
                async for linha in _linhas(arquivo, limite):
                    numero += 1
                    if numero < linha_inicial:
                        continue
                    if max_linhas is not None and devolvidas >= max_linhas:
                        ha_mais = True
                        break
                    if len(saida) + len(linha) > limite:
                        saida += linha[: limite - len(saida)]
                        truncado = True
                        break
                    saida += linha
                    devolvidas += 1
            finally:
                await arquivo.close()
            texto, usado = _decodificar(bytes(saida), encoding, cortado=truncado)
            return {
                "caminho": real,
                "tamanho": attrs.size,
                "encoding": usado,
                "linha_inicial": linha_inicial,
                "linhas_devolvidas": devolvidas,
                "truncado_no_limite_de_bytes": truncado,
                "ha_mais_linhas": ha_mais or truncado,
                "conteudo": texto,
                "_auditoria": {"bytes": len(saida)},
            }

        return await self._auditado(perfil, "ler", {"caminho": caminho}, executar)

    async def ultimas_linhas(
        self, nome_perfil: str, caminho: str, linhas: int = 100, encoding: str | None = None
    ) -> dict:
        _validar_encoding(encoding)
        if linhas < 1:
            raise ErroOperacao("linhas comeca em 1.")
        perfil = self._perfil(nome_perfil)

        async def executar(sftp):
            real, attrs, arquivo = await self._abrir_texto(perfil, sftp, caminho)
            if arquivo is None:
                return _binario(real, attrs)
            limite = perfil.max_leitura_bytes
            posicao = attrs.size
            dados = b""
            try:
                while posicao > 0 and dados.count(b"\n") <= linhas and len(dados) <= limite:
                    tamanho = min(_BLOCO, posicao)
                    posicao -= tamanho
                    dados = await arquivo.read(tamanho, posicao) + dados
            finally:
                await arquivo.close()
            partes = _separar_linhas(dados)
            # Sem ler o arquivo todo, a primeira linha lida pode estar pela metade.
            parcial = posicao > 0 and len(partes) == 1
            if posicao > 0 and len(partes) > 1:
                partes = partes[1:]
            partes = partes[-linhas:]
            truncado = False
            while len(partes) > 1 and sum(map(len, partes)) > limite:
                partes = partes[1:]
                truncado = True
            conteudo = b"".join(partes)
            if parcial or len(conteudo) > limite:
                # Ultima linha maior que o limite: devolve o final dela, sem
                # comecar no meio de um caractere UTF-8.
                conteudo = conteudo[-limite:]
                for _ in range(3):
                    if conteudo and conteudo[0] & 0xC0 == 0x80:
                        conteudo = conteudo[1:]
                truncado = True
            texto, usado = _decodificar(conteudo, encoding)
            return {
                "caminho": real,
                "tamanho": attrs.size,
                "encoding": usado,
                "linhas_devolvidas": len(partes),
                "truncado_no_limite_de_bytes": truncado,
                "conteudo": texto,
                "_auditoria": {"linhas": len(partes)},
            }

        return await self._auditado(perfil, "ultimas_linhas", {"caminho": caminho}, executar)

    async def buscar(
        self,
        nome_perfil: str,
        caminho: str,
        padrao: str = "*",
        tipo: str = "qualquer",
        profundidade: int | None = None,
        ordenar: str = "nome",
        limite: int | None = None,
    ) -> dict:
        if tipo not in ("qualquer", "arquivo", "pasta"):
            raise ErroOperacao("tipo deve ser qualquer, arquivo ou pasta.")
        _conferir_ordem_e_limite(ordenar, limite)
        perfil = self._perfil(nome_perfil)
        limite_profundidade = min(profundidade or perfil.busca_profundidade, perfil.busca_profundidade)
        maximo = min(limite or LIMITE_PADRAO, perfil.busca_max_resultados)

        def aceitar(nome: str, tipo_item: str) -> bool:
            return (tipo == "qualquer" or tipo_item == tipo) and fnmatch.fnmatch(nome.lower(), padrao.lower())

        async def executar(sftp):
            real, attrs = await self._stat_leitura(perfil, sftp, caminho)
            if _tipo(attrs) != "pasta":
                raise ErroOperacao(f"{real} nao e pasta.")
            v = await _varrer(sftp, real, limite_profundidade, aceitar, perfil.busca_max_resultados)
            achados = _ordenados(v.achados, ordenar, pastas_primeiro=False)
            resultados = [_descrever(c, a) for c, a in achados[:maximo]]
            return {
                "caminho": real,
                "padrao": padrao,
                "profundidade": limite_profundidade,
                "ordenado_por": ordenar,
                "total_encontrado": len(achados),
                "resultados": resultados,
                "truncado": v.truncado or len(achados) > len(resultados),
                "interrompido_por_tempo": v.interrompido,
                # Busca truncada ou interrompida: a ordem vale so para o que foi achado.
                "ordenacao_parcial": v.truncado or v.interrompido,
                "pastas_sem_acesso": v.sem_acesso,
                "pastas_com_erro": v.com_erro,
                "_auditoria": {"padrao": padrao, "itens": len(resultados)},
            }

        return await self._auditado(perfil, "buscar", {"caminho": caminho}, executar)

    async def baixar(
        self, nome_perfil: str, caminho: str, padrao: str | None = None, profundidade: int | None = None
    ) -> dict:
        perfil = self._perfil(nome_perfil, exige_repositorio=True)
        limite_profundidade = min(profundidade or perfil.busca_profundidade, perfil.busca_profundidade)

        async def executar(sftp):
            real, attrs = await self._stat_leitura(perfil, sftp, caminho)
            if _tipo(attrs) == "pasta":
                return await self._baixar_pasta(perfil, sftp, real, padrao or "*", limite_profundidade)
            if _tipo(attrs) != "arquivo":
                raise ErroOperacao(f"{real} nao e arquivo regular nem pasta.")
            destino = armazenamento.destino_download(perfil, real)
            tamanho, sha = await _baixar_um(sftp, real, destino)
            return {
                "caminho_remoto": real,
                "arquivo_local": str(destino),
                "tamanho": tamanho,
                "sha256": sha,
                "_auditoria": {"arquivo_local": str(destino), "tamanho": tamanho, "sha256": sha},
            }

        return await self._auditado(perfil, "baixar", {"caminho": caminho}, executar)

    async def _baixar_pasta(self, perfil: Perfil, sftp, real: str, padrao: str, profundidade: int) -> dict:
        def aceitar(nome: str, tipo_item: str) -> bool:
            return tipo_item == "arquivo" and fnmatch.fnmatch(nome.lower(), padrao.lower())

        v = await _varrer(sftp, real, profundidade, aceitar, LOTE_MAX_ARQUIVOS)
        if v.interrompido:
            raise ErroOperacao(
                f"A varredura de {real} passou de {TEMPO_MAX_VARREDURA} s. Restrinja com padrao ou profundidade."
            )
        if v.truncado:
            raise ErroOperacao(
                f"{real} tem mais de {LOTE_MAX_ARQUIVOS} arquivos com o padrao {padrao!r}. "
                "Filtre com padrao ou profundidade, ou baixe por subpasta. Nada foi baixado."
            )
        total = sum(a.size or 0 for _, a in v.achados)
        if total > LOTE_MAX_BYTES:
            raise ErroOperacao(
                f"O lote soma {total / 1e6:.0f} MB, acima do limite de {LOTE_MAX_BYTES // 1_000_000} MB. "
                "Filtre com padrao ou baixe por subpasta. Nada foi baixado."
            )
        resumo = {
            "caminho_remoto": real,
            "padrao": padrao,
            "pastas_sem_acesso": v.sem_acesso,
            "pastas_com_erro": v.com_erro,
        }
        if not v.achados:
            return {**resumo, "arquivos": 0, "_auditoria": {"arquivos": 0}}
        lote = armazenamento.nova_pasta_lote(perfil)
        # Reservado antes: um manifesto.json vindo do servidor ganha sufixo em vez de ser sobrescrito.
        arquivo_manifesto = armazenamento.destino_no_lote(lote, "manifesto.json")
        base = posixpath.dirname(real.rstrip("/")) or "/"
        manifesto, falhas = [], []
        for remoto, _attrs in sorted(v.achados):
            destino = armazenamento.destino_no_lote(lote, posixpath.relpath(remoto, base))
            try:
                tamanho, sha = await _baixar_um(sftp, remoto, destino)
            except (asyncssh.SFTPConnectionLost, asyncssh.SFTPNoConnection):
                raise
            except asyncssh.SFTPError as e:
                falhas.append({"caminho": remoto, "erro": _mensagem_sftp(e, remoto)})
                continue
            manifesto.append({
                "remoto": remoto, "local": destino.relative_to(lote).as_posix(), "tamanho": tamanho, "sha256": sha,
            })
        arquivo_manifesto.write_text(
            json.dumps(nomes.sanear({**resumo, "arquivos": manifesto, "falhas": falhas}), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        baixados = sum(m["tamanho"] for m in manifesto)
        return {
            **resumo,
            "pasta_local": str(lote),
            "arquivos": len(manifesto),
            "bytes": baixados,
            "falhas": falhas,
            "manifesto": str(arquivo_manifesto),
            "amostra": [m["local"] for m in manifesto[:20]],
            "_auditoria": {"lote": str(lote), "arquivos": len(manifesto), "bytes": baixados, "falhas": len(falhas)},
        }

    # ------------------------------------------------------------------
    # Escrita (as tools exigem aprovacao do usuario em toda chamada)

    async def _enviar_um(self, perfil: Perfil, sftp, origem: Path, real: str, atual) -> dict:
        backup = None
        if atual is not None:
            backup = armazenamento.destino_backup(perfil, real)
            try:
                await sftp.get(real, str(backup))
            except BaseException:
                backup.unlink(missing_ok=True)
                raise
        tamanho = origem.stat().st_size
        sha = _sha256(origem)
        # Grava num temporario da mesma pasta e troca no fim: queda no meio nao deixa o destino pela metade.
        temporario = posixpath.join(
            posixpath.dirname(real), f".{posixpath.basename(real)}.sftp-mcp-{secrets.token_hex(4)}.tmp"
        )
        direto = False
        try:
            await sftp.put(str(origem), temporario)
        except asyncssh.SFTPPermissionDenied:
            if atual is None:
                raise
            # Pasta sem permissao de criar arquivo, mas destino gravavel: grava direto nele, como o original.
            with contextlib.suppress(Exception):
                await sftp.remove(temporario)
            await sftp.put(str(origem), real)
            direto = True
        except BaseException:
            with contextlib.suppress(Exception):
                await sftp.remove(temporario)
            raise
        if direto:
            enviado = await sftp.stat(real)
            if enviado.size != tamanho:
                raise ErroOperacao(
                    f"Tamanho no servidor ({enviado.size}) difere do local ({tamanho}) em {real}. "
                    f"Versao anterior salva em {backup}."
                )
        else:
            try:
                enviado = await sftp.stat(temporario)
                if enviado.size != tamanho:
                    raise ErroOperacao(
                        f"Tamanho no servidor ({enviado.size}) difere do local ({tamanho}) em {real}. "
                        "O arquivo de destino nao foi tocado."
                    )
                if atual is None:
                    await sftp.rename(temporario, real)
                else:
                    # O arquivo novo nasce com o modo padrao do servidor: mantem o do arquivo substituido.
                    if atual.permissions is not None:
                        with contextlib.suppress(asyncssh.SFTPError):
                            await sftp.chmod(temporario, stat.S_IMODE(atual.permissions))
                    await _substituir(sftp, temporario, real, backup)
            except _DestinoApagado:
                raise
            except BaseException:
                with contextlib.suppress(Exception):
                    await sftp.remove(temporario)
                raise
        return {
            "caminho_remoto": real,
            "arquivo_local": str(origem),
            "tamanho": tamanho,
            "sha256": sha,
            "sobrescreveu": backup is not None,
            "backup_local": str(backup) if backup else None,
            "envio_direto": direto,
        }

    async def enviar(
        self, nome_perfil: str, arquivo_local: str, caminho_remoto: str, sobrescrever: bool = False
    ) -> dict:
        origem = _arquivo_local(arquivo_local)
        perfil = self._perfil(nome_perfil, exige_repositorio=True)

        async def executar(sftp):
            alvo = caminho_remoto + origem.name if caminho_remoto.endswith("/") else caminho_remoto
            real = await self._resolver_novo(sftp, alvo)
            atual = await self._lstat(sftp, real)
            if atual is not None and _tipo(atual) == "pasta":
                _validar_caminho(origem.name)
                real = posixpath.join(real, origem.name)
                atual = await self._lstat(sftp, real)
            await self._checar_escrita(perfil, sftp, real, estrito=True)
            _conferir_destino(real, atual, sobrescrever)
            dados = await self._enviar_um(perfil, sftp, origem, real, atual)
            return {**dados, "_auditoria": dict(dados)}

        return await self._auditado(
            perfil, "enviar", {"caminho": caminho_remoto, "sobrescrever": sobrescrever}, executar
        )

    async def enviar_lote(
        self, nome_perfil: str, arquivos_locais: list[str], pasta_remota: str, sobrescrever: bool = False
    ) -> dict:
        if not arquivos_locais:
            raise ErroOperacao("Informe ao menos um arquivo local.")
        if len(arquivos_locais) > LOTE_MAX_ENVIO:
            raise ErroOperacao(f"No maximo {LOTE_MAX_ENVIO} arquivos por lote.")
        origens = [_arquivo_local(a) for a in arquivos_locais]
        for origem in origens:
            _validar_caminho(origem.name)
        nomes_locais = [o.name for o in origens]
        repetidos = sorted({n for n in nomes_locais if nomes_locais.count(n) > 1})
        if repetidos:
            raise ErroOperacao(f"Nomes repetidos no lote: {', '.join(repetidos)}. Envie em lotes separados.")
        perfil = self._perfil(nome_perfil, exige_repositorio=True)

        async def executar(sftp):
            pasta_real = await self._resolver_existente(sftp, pasta_remota)
            try:
                attrs = await sftp.stat(pasta_real)
            except asyncssh.SFTPError as e:
                raise ErroOperacao(_mensagem_sftp(e, pasta_real)) from None
            if _tipo(attrs) != "pasta":
                raise ErroOperacao(f"{pasta_real} nao e pasta.")
            # Confere todos os destinos antes de enviar o primeiro: conflito nao deixa lote pela metade.
            planos = []
            for origem in origens:
                real = posixpath.join(pasta_real, origem.name)
                await self._checar_escrita(perfil, sftp, real, estrito=True)
                atual = await self._lstat(sftp, real)
                _conferir_destino(real, atual, sobrescrever)
                planos.append((origem, real, atual))
            enviados = []
            for origem, real, atual in planos:
                try:
                    enviados.append(await self._enviar_um(perfil, sftp, origem, real, atual))
                except Exception as e:
                    motivo = _mensagem_sftp(e, real) if isinstance(e, asyncssh.SFTPError) else str(e)
                    feitos = "; ".join(
                        d["caminho_remoto"] + (f" (backup em {d['backup_local']})" if d["backup_local"] else "")
                        for d in enviados
                    ) or "nenhum"
                    raise ErroOperacao(
                        f"Falhou em {real}: {motivo or type(e).__name__}. Enviados antes da falha: {feitos}."
                    ) from None
            return {
                "pasta_remota": pasta_real,
                "enviados": enviados,
                "_auditoria": {"enviados": [{k: d[k] for k in ("caminho_remoto", "sha256", "sobrescreveu")}
                                            for d in enviados]},
            }

        return await self._auditado(
            perfil, "enviar_lote",
            {"caminho": pasta_remota, "arquivos": nomes_locais, "sobrescrever": sobrescrever}, executar,
        )

    async def criar_pasta(self, nome_perfil: str, caminho: str, criar_pais: bool = False) -> dict:
        perfil = self._perfil(nome_perfil, exige_repositorio=True)

        async def executar(sftp):
            if criar_pais:
                real = await self._resolver_com_pais(sftp, caminho)
            else:
                real = await self._resolver_novo(sftp, caminho)
            await self._checar_escrita(perfil, sftp, real, estrito=True)
            if await self._lstat(sftp, real) is not None:
                raise ErroOperacao(f"{real} ja existe.")
            if criar_pais:
                await sftp.makedirs(real)
            else:
                await sftp.mkdir(real)
            return {"caminho": real, "_auditoria": {"criado": real}}

        return await self._auditado(perfil, "criar_pasta", {"caminho": caminho}, executar)

    async def renomear(self, nome_perfil: str, origem: str, destino: str) -> dict:
        perfil = self._perfil(nome_perfil, exige_repositorio=True)

        async def executar(sftp):
            # A origem nao segue o ultimo link: renomear um link mexe so no link.
            origem_real = await self._resolver_novo(sftp, origem)
            if await self._lstat(sftp, origem_real) is None:
                raise ErroOperacao(f"Nao existe no servidor: {origem_real}")
            destino_real = await self._resolver_novo(sftp, destino)
            await self._checar_escrita(perfil, sftp, origem_real, estrito=True)
            await self._checar_escrita(perfil, sftp, destino_real, estrito=True)
            if await self._lstat(sftp, destino_real) is not None:
                raise ErroOperacao(f"{destino_real} ja existe. Renomear nunca sobrescreve.")
            await sftp.rename(origem_real, destino_real)
            return {
                "origem": origem_real,
                "destino": destino_real,
                "_auditoria": {"origem_real": origem_real, "destino_real": destino_real},
            }

        return await self._auditado(perfil, "renomear", {"caminho": origem, "destino": destino}, executar)

    def vincular_repositorio(self, nome_perfil: str, caminho_repositorio: str) -> dict:
        perfil = config.obter_perfil(nome_perfil)
        pasta = Path(caminho_repositorio).expanduser()
        if not pasta.is_dir():
            raise ErroOperacao(f"Pasta nao existe: {pasta}")
        raiz = armazenamento.raiz_git(pasta)
        if raiz is None:
            raise ErroOperacao(f"{pasta} nao e repositorio git.")
        anterior = perfil.repositorio
        perfil.repositorio = str(raiz)
        config.salvar_perfil(perfil)
        pasta_local = armazenamento.pasta_perfil(perfil)
        aviso = armazenamento.aviso_git(raiz, perfil.nome)
        armazenamento.auditar(
            perfil, "vincular_repositorio", "ok", repositorio=str(raiz), anterior=anterior or None, aviso=aviso
        )
        return {"perfil": perfil.nome, "repositorio": str(raiz), "pasta_local": str(pasta_local), "aviso": aviso}


def _binario(real: str, attrs: asyncssh.SFTPAttrs) -> dict:
    descricao = _descrever(real, attrs)
    descricao["binario"] = True
    descricao["mensagem"] = "Arquivo binario: conteudo nao devolvido. Use sftp_baixar para trazer uma copia."
    return descricao


async def _linhas(arquivo, limite: int):
    """Linhas do arquivo em bytes, com o fim de linha. Linha maior que o limite vem cortada."""
    pendente = bytearray()
    cortada = False
    posicao = 0
    while True:
        bloco = await arquivo.read(_BLOCO, posicao)
        if not bloco:
            break
        posicao += len(bloco)
        inicio = 0
        while True:
            fim = bloco.find(b"\n", inicio)
            if fim < 0:
                if not cortada:
                    pendente += bloco[inicio:]
                    if len(pendente) > limite:
                        del pendente[limite + 1:]
                        cortada = True
                break
            if not cortada:
                pendente += bloco[inicio:fim + 1]
            yield bytes(pendente[: limite + 1])
            pendente.clear()
            cortada = False
            inicio = fim + 1
    if pendente:
        yield bytes(pendente)
