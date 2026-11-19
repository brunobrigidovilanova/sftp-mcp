"""Perfis de servidor SFTP: os do FileZilla, lidos a cada uso, e os gravados em ~/.sftp-mcp/perfis.toml.

Perfil do FileZilla tira host, porta, usuario, senha e chave do servidor de la; no
perfis.toml ficam so os ajustes dele (repositorio, raizes, limites). Perfil proprio do
perfis.toml (com host) segue o cadastro original: senha no keyring, chave fixada aqui.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

import tomli_w

from . import filezilla
from .ambiente import deduzir_ambiente

AMBIENTES = ("prod", "hml", "dev")
AUTENTICACOES = ("senha", "chave")
NOME_VALIDO = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
ORIGEM_FILEZILLA = "filezilla"
ORIGEM_TOML = "perfis.toml"
# Num perfil do FileZilla estes campos vem de la e nao podem ser sobrepostos no perfis.toml.
CAMPOS_FILEZILLA = ("host", "porta", "usuario", "host_key", "autenticacao", "chave_privada")


class ErroConfig(Exception):
    pass


def diretorio_config() -> Path:
    # SFTP_MCP_HOME existe para os testes e para quem quer a config em outro lugar.
    return Path(os.environ.get("SFTP_MCP_HOME") or Path.home() / ".sftp-mcp")


def arquivo_perfis() -> Path:
    return diretorio_config() / "perfis.toml"


@dataclass
class Perfil:
    nome: str
    host: str
    usuario: str
    host_key: str
    porta: int = 22
    autenticacao: str = "senha"
    chave_privada: str = ""
    ambiente: str = "dev"
    tspace_cliente: str = ""
    repositorio: str = ""
    pasta_inicial: str = ""
    raizes_leitura: list[str] = field(default_factory=list)
    raizes_escrita: list[str] = field(default_factory=list)
    timeout_conexao: int = 15
    ocioso_max_segundos: int = 300
    max_leitura_bytes: int = 1_048_576
    busca_profundidade: int = 5
    busca_max_resultados: int = 2000
    origem: str = ORIGEM_TOML

    def validar(self) -> None:
        if not NOME_VALIDO.match(self.nome):
            raise ErroConfig(
                f"Nome de perfil invalido: {self.nome!r}. Use letras minusculas, numeros e hifen."
            )
        if not self.host or not self.usuario:
            raise ErroConfig(f"Perfil {self.nome}: host e usuario sao obrigatorios.")
        if re.search(r"[/:@\s]", self.host):
            raise ErroConfig(
                f"Perfil {self.nome}: host {self.host!r} deve ser so o nome, sem sftp://, usuario ou porta."
            )
        if not self.host_key:
            raise ErroConfig(
                f"Perfil {self.nome}: sem host_key. Cadastre pelo setup para fixar a chave do servidor."
            )
        if self.autenticacao not in AUTENTICACOES:
            raise ErroConfig(f"Perfil {self.nome}: autenticacao deve ser {' ou '.join(AUTENTICACOES)}.")
        if self.autenticacao == "chave" and not self.chave_privada:
            raise ErroConfig(f"Perfil {self.nome}: autenticacao por chave sem chave_privada.")
        if self.ambiente not in AMBIENTES:
            raise ErroConfig(f"Perfil {self.nome}: ambiente deve ser {', '.join(AMBIENTES)}.")
        if self.pasta_inicial and not self.pasta_inicial.startswith("/"):
            raise ErroConfig(f"Perfil {self.nome}: pasta_inicial precisa ser caminho absoluto.")
        for raiz in self.raizes_leitura + self.raizes_escrita:
            if not raiz.startswith("/"):
                raise ErroConfig(f"Perfil {self.nome}: raiz {raiz!r} precisa ser caminho absoluto.")


_CAMPOS = {f.name for f in fields(Perfil)} - {"nome", "origem"}


def _ler_salvos() -> dict[str, dict]:
    arquivo = arquivo_perfis()
    if not arquivo.exists():
        return {}
    with arquivo.open("rb") as f:
        return dict(tomllib.load(f).get("perfis") or {})


def _gravar_salvos(salvos: dict[str, dict]) -> None:
    arquivo = arquivo_perfis()
    arquivo.parent.mkdir(parents=True, exist_ok=True)
    temporario = arquivo.with_suffix(".toml.tmp")
    temporario.write_bytes(tomli_w.dumps({"perfis": {n: salvos[n] for n in sorted(salvos)}}).encode("utf-8"))
    os.replace(temporario, arquivo)


def _conferir_campos(nome: str, valores: dict) -> None:
    desconhecidos = set(valores) - _CAMPOS
    if desconhecidos:
        raise ErroConfig(f"Perfil {nome}: campos desconhecidos {sorted(desconhecidos)}.")


def _perfil_proprio(nome: str, valores: dict) -> Perfil:
    _conferir_campos(nome, valores)
    try:
        perfil = Perfil(nome=nome, **valores)
    except TypeError:
        raise ErroConfig(
            f"Perfil {nome}: faltam host, usuario ou host_key no perfis.toml. Se ele vem do FileZilla, tire o host."
        ) from None
    perfil.validar()
    return perfil


def identidade(perfil: Perfil) -> str:
    return filezilla.identidade(perfil.host, perfil.porta, perfil.usuario)


def nome_segredo(perfil: Perfil) -> str:
    """Chave do segredo no keyring. No FileZilla e a conexao, nao o nome, que pode passar a outro site."""
    return f"filezilla:{identidade(perfil)}" if perfil.origem == ORIGEM_FILEZILLA else perfil.nome


def _perfil_filezilla(site: filezilla.Site, ajustes: dict) -> Perfil:
    ajustes = dict(ajustes)
    conexao = ajustes.pop("conexao", None)
    _conferir_campos(site.nome, ajustes)
    fixos = sorted(set(ajustes) & set(CAMPOS_FILEZILLA))
    if fixos:
        raise ErroConfig(
            f"Perfil {site.nome}: {', '.join(fixos)} vem do FileZilla. Altere no FileZilla e tire do perfis.toml."
        )
    atual = filezilla.identidade(site.host, site.porta, site.usuario)
    # Os ajustes (repositorio, raizes) valem para uma conexao, nao para o nome.
    if ajustes and conexao != atual:
        raise ErroConfig(
            f"Perfil {site.nome}: os ajustes no perfis.toml sao da conexao {conexao or '(nao registrada)'}, e o "
            f"FileZilla agora tem {atual} com esse nome. Se for a mesma, rode sftp-mcp-setup remover "
            f"{site.nome} e vincule o repositorio de novo."
        )
    valores = dict(
        host=site.host, porta=site.porta, usuario=site.usuario, host_key=site.host_key,
        autenticacao=site.autenticacao, chave_privada=site.chave_privada, ambiente=site.ambiente,
    )
    valores.update(ajustes)
    perfil = Perfil(nome=site.nome, origem=ORIGEM_FILEZILLA, **valores)
    perfil.validar()
    return perfil


def carregar_com_ignorados() -> tuple[dict[str, Perfil], list[dict]]:
    """Perfis prontos para uso e os que ficaram de fora, com o motivo (sem segredo)."""
    salvos = _ler_salvos()
    perfis = {nome: _perfil_proprio(nome, v) for nome, v in salvos.items() if "host" in v}
    ignorados: list[dict] = []
    try:
        sites, fora = filezilla.sites()
    except filezilla.ErroFileZilla as e:
        sites, fora = [], [filezilla.Ignorado("(filezilla)", str(e))]
    ignorados += [{"perfil": i.nome, "origem": ORIGEM_FILEZILLA, "motivo": i.motivo} for i in fora]
    # Site renomeado no FileZilla (ex.: salvo no Gerenciador de Sites) herda os ajustes da mesma conexao.
    por_conexao = {v["conexao"]: nome for nome, v in salvos.items() if "host" not in v and v.get("conexao")}
    adocoes = {}
    for site in sites:
        antigo = por_conexao.get(filezilla.identidade(site.host, site.porta, site.usuario))
        if site.nome not in salvos and antigo:
            adocoes[site.nome] = antigo
    adotados = set(adocoes.values())
    for site in sites:
        if site.nome in perfis:
            ignorados.append({
                "perfil": site.nome, "origem": ORIGEM_FILEZILLA,
                "motivo": "ja existe perfil proprio com esse nome no perfis.toml; renomeie o site no FileZilla",
            })
            continue
        if site.nome in adocoes:
            ajustes = salvos[adocoes[site.nome]]
        elif site.nome in adotados:
            ajustes = {}  # o nome passou a outra conexao; os ajustes seguiram a conexao dona deles
        else:
            ajustes = salvos.get(site.nome, {})
        try:
            perfis[site.nome] = _perfil_filezilla(site, ajustes)
        except ErroConfig as e:
            ignorados.append({"perfil": site.nome, "origem": ORIGEM_FILEZILLA, "motivo": str(e)})
    citados = {i["perfil"] for i in ignorados}
    for nome, valores in salvos.items():
        if "host" not in valores and nome not in perfis and nome not in citados and nome not in adotados:
            ignorados.append({
                "perfil": nome, "origem": ORIGEM_TOML,
                "motivo": "tem ajustes no perfis.toml, mas a conexao nao esta mais no FileZilla. A lista de "
                          "recentes do FileZilla e curta: salve a conexao no Gerenciador de Sites.",
            })
    return perfis, ignorados


def carregar_perfis() -> dict[str, Perfil]:
    return carregar_com_ignorados()[0]


def obter_perfil(nome: str) -> Perfil:
    perfis, ignorados = carregar_com_ignorados()
    if nome in perfis:
        return perfis[nome]
    for ignorado in ignorados:
        if ignorado["perfil"] == nome:
            raise ErroConfig(f"Perfil {nome!r} indisponivel: {ignorado['motivo']}")
    disponiveis = ", ".join(sorted(perfis)) or "nenhum cadastrado"
    raise ErroConfig(f"Perfil {nome!r} nao existe. Perfis: {disponiveis}.")


def _serializar(perfil: Perfil) -> dict:
    valores = asdict(perfil)
    del valores["nome"], valores["origem"]
    if perfil.origem != ORIGEM_FILEZILLA:
        return valores
    padrao = asdict(Perfil(
        nome=perfil.nome, host=perfil.host, usuario=perfil.usuario, host_key=perfil.host_key,
        ambiente=deduzir_ambiente(perfil.usuario),
    ))
    ajustes = {k: v for k, v in valores.items() if k not in CAMPOS_FILEZILLA and v != padrao[k]}
    return {**ajustes, "conexao": identidade(perfil)} if ajustes else {}


def salvar_perfil(perfil: Perfil) -> None:
    """Grava so este perfil e preserva os demais do arquivo, inclusive ajustes de conexao fora do FileZilla."""
    perfil.validar()
    salvos = _ler_salvos()
    valores = _serializar(perfil)
    if perfil.origem == ORIGEM_FILEZILLA:
        existente = salvos.get(perfil.nome)
        if existente and existente.get("conexao") not in (None, identidade(perfil)):
            # Ajustes de outra conexao ainda sob este nome: vao para o nome atual dela antes de gravar.
            dono = next((p for p in carregar_perfis().values()
                         if p.origem == ORIGEM_FILEZILLA and identidade(p) == existente["conexao"]), None)
            if dono is None:
                raise ErroConfig(
                    f"Os ajustes gravados sob {perfil.nome} sao da conexao {existente['conexao']}. "
                    f"Confira e rode sftp-mcp-setup remover {perfil.nome} antes de vincular de novo."
                )
            salvos[dono.nome] = existente
            del salvos[perfil.nome]
        _tirar_da_conexao(salvos, identidade(perfil))
    if valores:
        salvos[perfil.nome] = valores
    else:
        salvos.pop(perfil.nome, None)
    _gravar_salvos(salvos)


def _tirar_da_conexao(salvos: dict[str, dict], conexao: str) -> None:
    """Tira os ajustes da conexao gravados sob nome antigo do site."""
    for nome in [n for n, v in salvos.items() if "host" not in v and v.get("conexao") == conexao]:
        del salvos[nome]


def remover_perfil(nome: str, conexao: str | None = None) -> bool:
    """conexao, em perfil do FileZilla, tira tambem os ajustes herdados de nome antigo."""
    salvos = _ler_salvos()
    entrada = salvos.get(nome)
    removido = False
    # Sob este nome podem estar ajustes que seguiram outra conexao: esses ficam.
    if entrada is not None and (conexao is None or entrada.get("conexao") in (None, conexao)):
        del salvos[nome]
        removido = True
    if conexao:
        antes = len(salvos)
        _tirar_da_conexao(salvos, conexao)
        removido = removido or len(salvos) < antes
    if removido:
        _gravar_salvos(salvos)
    return removido
