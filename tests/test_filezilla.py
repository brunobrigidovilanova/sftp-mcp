"""Perfis lidos do FileZilla: recentes, Gerenciador de Sites, chaves aceitas e senha lida na hora."""

from __future__ import annotations

import base64
import dataclasses
import tomllib

import pytest

from sftp_mcp import config, credenciais, filezilla, setup
from sftp_mcp.conexao import ErroConexao, GerenciadorConexoes
from sftp_mcp.config import ErroConfig
from sftp_mcp.operacoes import Operacoes

from .conftest import SENHA, USUARIO

NOME = "127-0-0-1-dev"


def _servidor_xml(host, porta, usuario=USUARIO, senha=SENHA, *, protocolo="1", logon="1", nome=None,
                  encoding="base64") -> str:
    partes = [f"<Host>{host}</Host><Port>{porta}</Port><Protocol>{protocolo}</Protocol><User>{usuario}</User>"]
    if senha is not None:
        valor = base64.b64encode(senha.encode()).decode() if encoding == "base64" else senha
        partes.append(f'<Pass encoding="{encoding}">{valor}</Pass>')
    partes.append(f"<Logontype>{logon}</Logontype>")
    if nome is not None:
        partes.append(f"<Name>{nome}</Name>")
    return "<Server>" + "".join(partes) + "</Server>"


def _gravar(nome: str, conteudo: str) -> None:
    pasta = filezilla.pasta()
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / nome).write_text(f'<?xml version="1.0" encoding="UTF-8"?>\n{conteudo}', encoding="utf-8")


def _recentes(*servidores: str) -> None:
    _gravar("recentservers.xml", f"<FileZilla3><RecentServers>{''.join(servidores)}</RecentServers></FileZilla3>")


def _sites(conteudo: str) -> None:
    _gravar("sitemanager.xml", f"<FileZilla3><Servers>{conteudo}</Servers></FileZilla3>")


def _chave_aceita(host, porta, chave) -> None:
    blob = chave.export_public_key("openssh").decode().split()[1]
    _gravar(
        "hostkeys.xml",
        f'<FileZilla3><Server Host="{host}" Port="{porta}"><Hostkey>{blob}</Hostkey></Server></FileZilla3>',
    )


@pytest.fixture
def no_filezilla(servidor, chave_host):
    _recentes(_servidor_xml("127.0.0.1", servidor))
    _chave_aceita("127.0.0.1", servidor, chave_host)
    return servidor


def _conexao(porta) -> str:
    return f"{USUARIO}@127.0.0.1:{porta}"


def _salvos() -> dict:
    arquivo = config.arquivo_perfis()
    return tomllib.loads(arquivo.read_text(encoding="utf-8"))["perfis"] if arquivo.exists() else {}


async def test_recente_vira_perfil_e_conecta_com_a_senha_do_filezilla(no_filezilla, chave_host, repositorio, ops):
    perfil = config.obter_perfil(NOME)
    assert perfil.origem == config.ORIGEM_FILEZILLA
    assert perfil.host_key == chave_host.export_public_key("openssh").decode().strip()
    assert credenciais.obter(NOME, "senha") is None
    ops.vincular_repositorio(NOME, str(repositorio))
    resultado = await ops.listar(NOME, "/")
    assert {e["nome"] for e in resultado["entradas"]} >= {"escrita", "logs"}


async def test_vincular_grava_so_o_ajuste_no_toml(no_filezilla, repositorio, ops):
    ops.vincular_repositorio(NOME, str(repositorio))
    assert _salvos() == {NOME: {"repositorio": str(repositorio), "conexao": _conexao(no_filezilla)}}
    assert config.obter_perfil(NOME).repositorio == str(repositorio)


async def test_senha_e_lida_do_filezilla_a_cada_conexao(servidor, chave_host, repositorio):
    _recentes(_servidor_xml("127.0.0.1", servidor, senha="errada"))
    _chave_aceita("127.0.0.1", servidor, chave_host)
    ops = Operacoes(GerenciadorConexoes())
    ops.vincular_repositorio(NOME, str(repositorio))
    with pytest.raises(ErroConexao, match="Autenticacao recusada"):
        await ops.listar(NOME, "/")
    _recentes(_servidor_xml("127.0.0.1", servidor))
    try:
        assert (await ops.listar(NOME, "/"))["entradas"]
    finally:
        await ops._gerenciador.fechar_todas()


def test_gerenciador_de_sites_tem_prioridade_e_da_o_nome(servidor, chave_host):
    _sites(f"<Folder>Clientes{_servidor_xml('127.0.0.1', servidor, nome='Cliente Produção')}</Folder>")
    _recentes(_servidor_xml("127.0.0.1", servidor))
    _chave_aceita("127.0.0.1", servidor, chave_host)
    assert list(config.carregar_perfis()) == ["cliente-producao"]


def test_nome_e_ambiente_do_recente_do_tcloud(chave_host):
    host = "clientex123456.protheus.cloudtotvs.com.br"
    _recentes(_servidor_xml(host, 11351, "ftp_ABC123_production"))
    _chave_aceita(host, 11351, chave_host)
    perfil = config.obter_perfil("clientex123456-prod")
    assert (perfil.ambiente, perfil.host, perfil.porta) == ("prod", host, 11351)


def test_sem_chave_aceita_fica_indisponivel_com_motivo(servidor, ops):
    _recentes(_servidor_xml("127.0.0.1", servidor))
    assert config.carregar_perfis() == {}
    with pytest.raises(ErroConfig, match="indisponivel.*chave aceita"):
        config.obter_perfil(NOME)
    [item] = ops.perfis()
    assert (item["perfil"], item["origem"]) == (NOME, "filezilla")
    assert "aceite a chave" in item["indisponivel"]


def test_ftp_e_logon_anonimo_ficam_de_fora(chave_host):
    _recentes(
        _servidor_xml("ftp.exemplo.com", 21, protocolo="0"),
        _servidor_xml("sftp.exemplo.com", 22, logon="0"),
    )
    _chave_aceita("sftp.exemplo.com", 22, chave_host)
    perfis, ignorados = config.carregar_com_ignorados()
    assert perfis == {}
    motivos = " | ".join(i["motivo"] for i in ignorados)
    assert "nao e SFTP" in motivos and "logon 0" in motivos


async def test_senha_mestra_nao_e_lida_e_o_keyring_serve_de_reserva(servidor, chave_host, repositorio, ops):
    _recentes(_servidor_xml("127.0.0.1", servidor, senha="cifrada", encoding="crypt"))
    _chave_aceita("127.0.0.1", servidor, chave_host)
    ops.vincular_repositorio(NOME, str(repositorio))
    assert filezilla.senha("127.0.0.1", servidor, USUARIO) is None
    with pytest.raises(ErroConexao, match="sem senha salva no FileZilla"):
        await ops.listar(NOME, "/")
    # A reserva vale pela conexao: segredo gravado so pelo nome do perfil nao e usado.
    credenciais.gravar(NOME, "senha", SENHA)
    with pytest.raises(ErroConexao, match="sem senha salva no FileZilla"):
        await ops.listar(NOME, "/")
    credenciais.gravar(config.nome_segredo(config.obter_perfil(NOME)), "senha", SENHA)
    assert (await ops.listar(NOME, "/"))["entradas"]


def test_perfis_nao_mostra_a_senha(no_filezilla, ops):
    texto = str(ops.perfis())
    assert SENHA not in texto and base64.b64encode(SENHA.encode()).decode() not in texto
    assert ops.perfis()[0]["segredo_cadastrado"] is True


def test_identidade_no_toml_e_recusada(no_filezilla):
    config._gravar_salvos({NOME: {"usuario": "outro"}})
    perfis, ignorados = config.carregar_com_ignorados()
    assert NOME not in perfis
    assert "vem do FileZilla" in ignorados[0]["motivo"]


def test_ajuste_de_ambiente_vale_e_continua_gravado(no_filezilla, repositorio, ops):
    config._gravar_salvos({NOME: {"ambiente": "prod", "conexao": _conexao(no_filezilla)}})
    assert config.obter_perfil(NOME).ambiente == "prod"
    ops.vincular_repositorio(NOME, str(repositorio))
    assert _salvos()[NOME] == {"ambiente": "prod", "repositorio": str(repositorio), "conexao": _conexao(no_filezilla)}


def test_ajuste_orfao_nao_derruba_os_outros(no_filezilla):
    config._gravar_salvos({"sumiu": {"repositorio": "C:/repo"}})
    perfis, ignorados = config.carregar_com_ignorados()
    assert list(perfis) == [NOME]
    assert ignorados[0]["perfil"] == "sumiu" and "Gerenciador de Sites" in ignorados[0]["motivo"]


def test_vincular_outro_perfil_preserva_ajuste_orfao(no_filezilla, repositorio, ops):
    config._gravar_salvos({"sumiu": {"repositorio": "C:/repo"}})
    ops.vincular_repositorio(NOME, str(repositorio))
    assert _salvos()["sumiu"] == {"repositorio": "C:/repo"}


def test_xml_corrompido_nao_derruba_perfil_proprio(perfil):
    _gravar("recentservers.xml", "<FileZilla3><RecentServers>")
    perfis, ignorados = config.carregar_com_ignorados()
    assert list(perfis) == [perfil.nome]
    assert ignorados[0]["perfil"] == "(filezilla)"


def test_perfil_proprio_com_mesmo_nome_ganha(perfil, servidor, chave_host):
    _sites(_servidor_xml("127.0.0.1", servidor, nome=perfil.nome))
    _chave_aceita("127.0.0.1", servidor, chave_host)
    perfis, ignorados = config.carregar_com_ignorados()
    assert perfis[perfil.nome].origem == config.ORIGEM_TOML
    assert "perfil proprio" in ignorados[0]["motivo"]


def test_chave_openssh_converte_o_blob(chave_host):
    esperado = chave_host.export_public_key("openssh").decode().strip()
    assert filezilla.chave_openssh(esperado.split()[1]) == esperado
    assert filezilla.chave_openssh("isso-nao-e-chave") == ""


def test_setup_manda_trocar_chave_e_senha_pelo_filezilla(no_filezilla):
    with pytest.raises(SystemExit, match="vem do FileZilla"):
        setup.trocar_fingerprint(NOME)
    with pytest.raises(SystemExit, match="vem do FileZilla"):
        setup.definir_senha(NOME)


def test_setup_remover_tira_so_o_ajuste(no_filezilla, repositorio, ops, capsys):
    ops.vincular_repositorio(NOME, str(repositorio))
    setup.remover(NOME)
    assert _salvos() == {}
    assert "continua no FileZilla" in capsys.readouterr().out
    assert NOME in config.carregar_perfis()


def test_nome_repetido_tira_todas_as_conexoes_com_ele(servidor, chave_host):
    _sites(
        f"<Folder>Cliente A{_servidor_xml('127.0.0.1', servidor, nome='Producao')}</Folder>"
        f"<Folder>Cliente B{_servidor_xml('localhost', servidor, nome='Producao')}</Folder>"
    )
    blob = chave_host.export_public_key("openssh").decode().split()[1]
    _gravar("hostkeys.xml", "<FileZilla3>" + "".join(
        f'<Server Host="{h}" Port="{servidor}"><Hostkey>{blob}</Hostkey></Server>' for h in ("127.0.0.1", "localhost")
    ) + "</FileZilla3>")
    perfis, ignorados = config.carregar_com_ignorados()
    assert "producao" not in perfis
    assert any(i["perfil"] == "producao" and "repetido" in i["motivo"] for i in ignorados)


def test_ajuste_de_outra_conexao_deixa_o_perfil_indisponivel(no_filezilla):
    config._gravar_salvos({NOME: {"repositorio": "C:/repo-a", "conexao": "outro@clientea.com:22"}})
    with pytest.raises(ErroConfig, match="sao da conexao outro@clientea.com:22"):
        config.obter_perfil(NOME)
    config._gravar_salvos({NOME: {"repositorio": "C:/repo-a"}})
    with pytest.raises(ErroConfig, match="nao registrada"):
        config.obter_perfil(NOME)


def test_ambiente_do_nome_do_site_quando_o_usuario_nao_diz(servidor, chave_host):
    _sites(_servidor_xml("127.0.0.1", servidor, nome="Cliente X Produção"))
    _chave_aceita("127.0.0.1", servidor, chave_host)
    assert config.obter_perfil("cliente-x-producao").ambiente == "prod"


def test_host_no_ajuste_da_erro_claro(no_filezilla):
    config._gravar_salvos({NOME: {"host": "outro.com"}})
    with pytest.raises(ErroConfig, match="faltam host, usuario ou host_key"):
        config.carregar_perfis()


async def test_conexao_em_cache_e_trocada_quando_o_destino_muda(perfil, ops):
    gerenciador = ops._gerenciador
    async with gerenciador.usar(perfil) as sftp:
        assert await sftp.realpath(".") == "/"
    primeira = gerenciador._conexoes[perfil.nome]
    outro = dataclasses.replace(perfil, pasta_inicial="/logs")
    async with gerenciador.usar(outro) as sftp:
        assert await sftp.realpath(".") == "/logs"
    assert gerenciador._conexoes[perfil.nome] is not primeira
