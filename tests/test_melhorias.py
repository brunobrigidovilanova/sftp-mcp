"""Limite e ordem na listagem, busca com teto de tempo, download e envio em lote, envio atomico e
heranca de ajustes quando o site e renomeado no FileZilla."""

from __future__ import annotations

import json
import os

import asyncssh
import pytest

from sftp_mcp import config, operacoes, setup
from sftp_mcp.operacoes import ErroOperacao

from .conftest import pasta_local
from .test_filezilla import NOME, _chave_aceita, _conexao, _recentes, _servidor_xml, _sites


def _arquivos(pasta, quantidade, prefixo="a"):
    for i in range(quantidade):
        arquivo = pasta / f"{prefixo}{i:03}.log"
        arquivo.write_text("x" * (i + 1))
        os.utime(arquivo, (1_700_000_000 + i, 1_700_000_000 + i))


# ---------------------------------------------------------------- listar e buscar

async def test_listar_limita_e_informa_o_total(ops, perfil, remoto):
    _arquivos(remoto / "logs", 250)
    resultado = await ops.listar(perfil.nome, "/logs")
    assert (resultado["total"], len(resultado["entradas"]), resultado["truncado"]) == (250, 200, True)
    resultado = await ops.listar(perfil.nome, "/logs", limite=5)
    assert len(resultado["entradas"]) == 5


async def test_listar_ordena_pelo_mais_recente_e_pelo_maior(ops, perfil, remoto):
    _arquivos(remoto / "logs", 10)
    recentes = await ops.listar(perfil.nome, "/logs", ordenar="modificado", limite=2)
    assert [e["nome"] for e in recentes["entradas"]] == ["a009.log", "a008.log"]
    maiores = await ops.listar(perfil.nome, "/logs", ordenar="tamanho", limite=1)
    assert maiores["entradas"][0]["tamanho"] == 10


async def test_ordem_e_limite_invalidos(ops, perfil):
    with pytest.raises(ErroOperacao, match="ordenar"):
        await ops.listar(perfil.nome, "/", ordenar="data")
    with pytest.raises(ErroOperacao, match="limite"):
        await ops.buscar(perfil.nome, "/", limite=0)


async def test_buscar_ordena_e_limita(ops, perfil, remoto):
    (remoto / "logs" / "sub").mkdir()
    _arquivos(remoto / "logs" / "sub", 30)
    resultado = await ops.buscar(perfil.nome, "/", "*.log", ordenar="modificado", limite=3)
    assert resultado["total_encontrado"] == 30 and resultado["truncado"]
    assert [r["caminho"] for r in resultado["resultados"]][0] == "/logs/sub/a029.log"


async def test_buscar_para_no_teto_de_tempo(ops, perfil, monkeypatch):
    monkeypatch.setattr(operacoes, "TEMPO_MAX_VARREDURA", -1)
    resultado = await ops.buscar(perfil.nome, "/")
    assert resultado["interrompido_por_tempo"] and resultado["resultados"] == []


async def test_buscar_pula_pasta_com_erro_e_continua(ops, perfil, remoto, monkeypatch):
    (remoto / "logs" / "ok.log").write_text("x")
    original = asyncssh.SFTPClient.readdir

    async def readdir(self, caminho="."):
        if str(caminho).endswith("/fora"):
            raise asyncssh.SFTPFailure("falha generica")
        return await original(self, caminho)

    monkeypatch.setattr(asyncssh.SFTPClient, "readdir", readdir)
    resultado = await ops.buscar(perfil.nome, "/", "*.log")
    assert [r["caminho"] for r in resultado["resultados"]] == ["/logs/ok.log"]
    assert resultado["pastas_com_erro"][0]["pasta"] == "/fora"


# ---------------------------------------------------------------- download em lote

async def test_baixar_pasta_num_lote_com_manifesto(ops, perfil, remoto):
    (remoto / "logs" / "fact").mkdir()
    (remoto / "logs" / "a.sql").write_text("select 1")
    (remoto / "logs" / "fact" / "b.sql").write_text("select 2")
    (remoto / "logs" / "c.txt").write_text("fora do padrao")
    resultado = await ops.baixar(perfil.nome, "/logs", padrao="*.sql")
    assert resultado["arquivos"] == 2 and resultado["falhas"] == []
    lote = pasta_local(perfil) / "downloads" / os.path.basename(resultado["pasta_local"])
    assert (lote / "logs" / "a.sql").read_text() == "select 1"
    assert (lote / "logs" / "fact" / "b.sql").read_text() == "select 2"
    manifesto = json.loads((lote / "manifesto.json").read_text(encoding="utf-8"))
    assert {m["remoto"] for m in manifesto["arquivos"]} == {"/logs/a.sql", "/logs/fact/b.sql"}
    segundo = await ops.baixar(perfil.nome, "/logs", padrao="*.sql")
    assert segundo["pasta_local"] != resultado["pasta_local"]


async def test_lote_grande_demais_nao_baixa_nada(ops, perfil, remoto, monkeypatch):
    _arquivos(remoto / "logs", 3)
    monkeypatch.setattr(operacoes, "LOTE_MAX_ARQUIVOS", 2)
    with pytest.raises(ErroOperacao, match="mais de 2 arquivos"):
        await ops.baixar(perfil.nome, "/logs")
    assert not (pasta_local(perfil) / "downloads").exists()
    monkeypatch.setattr(operacoes, "LOTE_MAX_ARQUIVOS", 500)
    monkeypatch.setattr(operacoes, "LOTE_MAX_BYTES", 2)
    with pytest.raises(ErroOperacao, match="acima do limite"):
        await ops.baixar(perfil.nome, "/logs")


# ---------------------------------------------------------------- envio atomico e em lote

def _sem_temporarios(pasta):
    return not [p.name for p in pasta.iterdir() if ".sftp-mcp-" in p.name]


async def test_envio_nao_deixa_temporario(ops, perfil, remoto, tmp_path):
    local = tmp_path / "novo.ini"
    local.write_text("[novo]")
    await ops.enviar(perfil.nome, str(local), "/escrita/")
    assert (remoto / "escrita" / "novo.ini").read_text() == "[novo]"
    assert _sem_temporarios(remoto / "escrita")


async def test_queda_no_envio_preserva_o_destino(ops, perfil, remoto, tmp_path, monkeypatch):
    (remoto / "escrita" / "appserver.ini").write_text("versao antiga")
    local = tmp_path / "appserver.ini"
    local.write_text("versao nova")

    async def put_que_cai(self, origem, destino, **_):
        (remoto / destino.lstrip("/")).write_text("vers")
        raise asyncssh.SFTPConnectionLost("caiu")

    monkeypatch.setattr(asyncssh.SFTPClient, "put", put_que_cai)
    with pytest.raises(ErroOperacao, match="caiu"):
        await ops.enviar(perfil.nome, str(local), "/escrita/appserver.ini", sobrescrever=True)
    assert (remoto / "escrita" / "appserver.ini").read_text() == "versao antiga"
    assert _sem_temporarios(remoto / "escrita")


async def test_sobrescrever_sem_posix_rename(ops, perfil, remoto, tmp_path, monkeypatch):
    (remoto / "escrita" / "x.txt").write_text("antes")
    local = tmp_path / "x.txt"
    local.write_text("depois")

    async def sem_extensao(self, *_):
        raise asyncssh.SFTPOpUnsupported("sem posix-rename")

    monkeypatch.setattr(asyncssh.SFTPClient, "posix_rename", sem_extensao)
    resultado = await ops.enviar(perfil.nome, str(local), "/escrita/x.txt", sobrescrever=True)
    assert (remoto / "escrita" / "x.txt").read_text() == "depois"
    assert open(resultado["backup_local"], encoding="utf-8").read() == "antes"
    assert _sem_temporarios(remoto / "escrita")


async def test_enviar_lote(ops, perfil, remoto, tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("A")
    b.write_text("B")
    resultado = await ops.enviar_lote(perfil.nome, [str(a), str(b)], "/escrita")
    assert [d["caminho_remoto"] for d in resultado["enviados"]] == ["/escrita/a.txt", "/escrita/b.txt"]
    assert (remoto / "escrita" / "b.txt").read_text() == "B"


async def test_enviar_lote_com_conflito_nao_envia_nenhum(ops, perfil, remoto, tmp_path):
    (remoto / "escrita" / "b.txt").write_text("existente")
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("A")
    b.write_text("B")
    with pytest.raises(ErroOperacao, match="ja existe"):
        await ops.enviar_lote(perfil.nome, [str(a), str(b)], "/escrita")
    assert not (remoto / "escrita" / "a.txt").exists()
    await ops.enviar_lote(perfil.nome, [str(a), str(b)], "/escrita", sobrescrever=True)
    assert (remoto / "escrita" / "b.txt").read_text() == "B"


async def test_enviar_lote_recusa_nome_repetido_e_fora_da_raiz(ops, perfil, tmp_path):
    (tmp_path / "um").mkdir()
    (tmp_path / "dois").mkdir()
    (tmp_path / "um" / "x.txt").write_text("1")
    (tmp_path / "dois" / "x.txt").write_text("2")
    with pytest.raises(ErroOperacao, match="Nomes repetidos"):
        await ops.enviar_lote(perfil.nome, [str(tmp_path / "um" / "x.txt"), str(tmp_path / "dois" / "x.txt")], "/escrita")
    with pytest.raises(ErroOperacao, match="fora das raizes de escrita"):
        await ops.enviar_lote(perfil.nome, [str(tmp_path / "um" / "x.txt")], "/fora")


# ---------------------------------------------------------------- site renomeado no FileZilla

async def test_site_renomeado_herda_o_vinculo(servidor, chave_host, repositorio, ops):
    _recentes(_servidor_xml("127.0.0.1", servidor))
    _chave_aceita("127.0.0.1", servidor, chave_host)
    ops.vincular_repositorio(NOME, str(repositorio))
    # O usuario salva a conexao no Gerenciador de Sites com outro nome.
    _sites(_servidor_xml("127.0.0.1", servidor, nome="Cliente Dev"))
    perfis, ignorados = config.carregar_com_ignorados()
    assert perfis["cliente-dev"].repositorio == str(repositorio)
    assert not ignorados
    ops.vincular_repositorio("cliente-dev", str(repositorio))
    assert list(config._ler_salvos()) == ["cliente-dev"]
    assert config._ler_salvos()["cliente-dev"]["conexao"] == _conexao(servidor)


# ---------------------------------------------------------------- achados da segunda revisao

async def test_troca_sem_posix_rename_que_falha_preserva_o_novo(ops, perfil, remoto, tmp_path, monkeypatch):
    (remoto / "escrita" / "x.ini").write_text("antes")
    local = tmp_path / "x.ini"
    local.write_text("depois")

    async def sem_extensao(self, *_):
        raise asyncssh.SFTPOpUnsupported("sem posix-rename")

    original = asyncssh.SFTPClient.rename

    async def rename(self, antigo, novo, *a, **k):
        if ".sftp-mcp-" in str(antigo) and str(novo).endswith("/x.ini"):
            raise asyncssh.SFTPFailure("falha no rename")
        return await original(self, antigo, novo, *a, **k)

    monkeypatch.setattr(asyncssh.SFTPClient, "posix_rename", sem_extensao)
    monkeypatch.setattr(asyncssh.SFTPClient, "rename", rename)
    with pytest.raises(ErroOperacao, match="foi apagado para a troca"):
        await ops.enviar(perfil.nome, str(local), "/escrita/x.ini", sobrescrever=True)
    temporarios = [p for p in (remoto / "escrita").iterdir() if ".sftp-mcp-" in p.name]
    assert len(temporarios) == 1 and temporarios[0].read_text() == "depois"


async def test_sobrescrever_mantem_o_modo_do_arquivo(ops, perfil, remoto, tmp_path, monkeypatch):
    (remoto / "escrita" / "x.sh").write_text("antes")
    local = tmp_path / "x.sh"
    local.write_text("depois")
    original_lstat = asyncssh.SFTPClient.lstat
    modos = []

    async def lstat(self, caminho):
        attrs = await original_lstat(self, caminho)
        if str(caminho).endswith("/x.sh"):
            attrs.permissions = 0o100750
        return attrs

    async def chmod(self, caminho, modo, *a, **k):
        modos.append((str(caminho), modo))

    monkeypatch.setattr(asyncssh.SFTPClient, "lstat", lstat)
    monkeypatch.setattr(asyncssh.SFTPClient, "chmod", chmod)
    await ops.enviar(perfil.nome, str(local), "/escrita/x.sh", sobrescrever=True)
    assert modos and ".sftp-mcp-" in modos[0][0] and modos[0][1] == 0o750


async def test_pasta_sem_permissao_de_criar_grava_direto(ops, perfil, remoto, tmp_path, monkeypatch):
    (remoto / "escrita" / "x.ini").write_text("antes")
    local = tmp_path / "x.ini"
    local.write_text("depois")
    original = asyncssh.SFTPClient.put

    async def put(self, origem, destino, *a, **k):
        if ".sftp-mcp-" in str(destino):
            raise asyncssh.SFTPPermissionDenied("sem permissao na pasta")
        return await original(self, origem, destino, *a, **k)

    monkeypatch.setattr(asyncssh.SFTPClient, "put", put)
    resultado = await ops.enviar(perfil.nome, str(local), "/escrita/x.ini", sobrescrever=True)
    assert resultado["envio_direto"] and (remoto / "escrita" / "x.ini").read_text() == "depois"
    assert open(resultado["backup_local"], encoding="utf-8").read() == "antes"


async def test_queda_no_meio_do_lote_lista_o_que_foi_enviado(ops, perfil, remoto, tmp_path, monkeypatch):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("A")
    b.write_text("B")
    original = asyncssh.SFTPClient.put

    async def put(self, origem, destino, *x, **k):
        if str(origem).endswith("b.txt"):
            raise asyncssh.SFTPConnectionLost("caiu")
        return await original(self, origem, destino, *x, **k)

    monkeypatch.setattr(asyncssh.SFTPClient, "put", put)
    with pytest.raises(ErroOperacao, match="Enviados antes da falha: /escrita/a.txt"):
        await ops.enviar_lote(perfil.nome, [str(a), str(b)], "/escrita")
    auditoria = (pasta_local(perfil) / "audit.log").read_text(encoding="utf-8")
    assert "/escrita/a.txt" in auditoria


async def test_lote_recusa_nome_com_caractere_invisivel(ops, perfil, tmp_path):
    estranho = tmp_path / "relatorio\u202etxt.exe"
    estranho.write_text("x")
    with pytest.raises(ErroOperacao, match="invisivel"):
        await ops.enviar_lote(perfil.nome, [str(estranho)], "/escrita")


async def test_manifesto_do_servidor_nao_e_sobrescrito(ops, perfil, remoto):
    (remoto / "manifesto.json").write_text("do servidor")
    resultado = await ops.baixar(perfil.nome, "/", padrao="manifesto.json", profundidade=1)
    lote = os.path.dirname(resultado["manifesto"])
    assert json.loads(open(resultado["manifesto"], encoding="utf-8").read())["arquivos"][0]["remoto"] == "/manifesto.json"
    assert open(os.path.join(lote, "manifesto (1).json"), encoding="utf-8").read() == "do servidor"


async def test_busca_truncada_avisa_ordem_parcial(ops, perfil, remoto):
    perfil.busca_max_resultados = 5
    config.salvar_perfil(perfil)
    _arquivos(remoto / "logs", 10)
    resultado = await ops.buscar(perfil.nome, "/logs", "*.log", ordenar="modificado", limite=1)
    assert resultado["ordenacao_parcial"] and resultado["truncado"]


def _dois_sites(servidor, chave_host, nome_a, nome_b):
    """A = 127.0.0.1, B = localhost: mesma porta, conexoes diferentes."""
    from .test_filezilla import _gravar
    _sites(_servidor_xml("127.0.0.1", servidor, nome=nome_a) + _servidor_xml("localhost", servidor, nome=nome_b))
    blob = chave_host.export_public_key("openssh").decode().split()[1]
    _gravar("hostkeys.xml", "<FileZilla3>" + "".join(
        f'<Server Host="{h}" Port="{servidor}"><Hostkey>{blob}</Hostkey></Server>' for h in ("127.0.0.1", "localhost")
    ) + "</FileZilla3>")


async def test_heranca_com_nome_antigo_ocupado_por_outra_conexao(servidor, chave_host, repositorio, ops, capsys):
    config._gravar_salvos({"antigo": {
        "repositorio": str(repositorio), "raizes_escrita": ["/escrita"], "conexao": _conexao(servidor),
    }})
    _dois_sites(servidor, chave_host, "Novo", "Antigo")
    perfis, _ = config.carregar_com_ignorados()
    assert perfis["novo"].raizes_escrita == ["/escrita"]
    assert perfis["antigo"].raizes_escrita == [] and perfis["antigo"].repositorio == ""
    setup.remover("antigo")
    assert config.obter_perfil("novo").raizes_escrita == ["/escrita"]
    ops.vincular_repositorio("antigo", str(repositorio))
    salvos = config._ler_salvos()
    assert salvos["novo"]["raizes_escrita"] == ["/escrita"] and salvos["novo"]["conexao"] == _conexao(servidor)
    assert salvos["antigo"]["conexao"] == f"cliente@localhost:{servidor}"
