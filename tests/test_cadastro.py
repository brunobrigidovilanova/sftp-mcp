from __future__ import annotations

import json

import pytest

from sftp_mcp import ambiente, cadastro, config, credenciais
from sftp_mcp.conexao import ErroConexao, chave_do_servidor
from sftp_mcp.operacoes import ErroOperacao

from .conftest import SENHA, USUARIO


def _perfil(servidor, chave, url=None, nome="novo-dev") -> config.Perfil:
    host, porta, rota = cadastro.separar_url(url or f"sftp://127.0.0.1:{servidor}")
    return config.Perfil(
        nome=nome, host=host, porta=porta or 22, usuario=USUARIO, host_key=chave, ambiente="dev",
        pasta_inicial=rota,
    )


@pytest.mark.parametrize(
    "usuario, esperado",
    [
        ("ftp_CUP8TG_development", "dev"),
        ("ftp_C56YW4_production", "prod"),
        ("ftp_C56YW4_staging", "hml"),
        ("ftp_ABC_homolog", "hml"),
        ("usuario_qualquer", "dev"),
        ("", "dev"),
    ],
)
def test_deduz_ambiente_sem_dar_erro(usuario, esperado):
    assert ambiente.deduzir_ambiente(usuario) == esperado


async def test_cadastro_completo(servidor, repositorio):
    chave = await chave_do_servidor("127.0.0.1", servidor)
    assert not cadastro.chave_conhecida(chave)
    resultado = await cadastro.registrar(_perfil(servidor, chave), SENHA, str(repositorio))
    assert resultado["status"] == "cadastrado" and resultado["aviso"] is None
    assert SENHA not in json.dumps(resultado)
    perfil = config.obter_perfil("novo-dev")
    assert perfil.raizes_escrita == [] and perfil.repositorio
    assert credenciais.obter("novo-dev", "senha") == SENHA
    assert cadastro.chave_conhecida(chave)


async def test_senha_errada_nao_deixa_nada_gravado(servidor):
    chave = await chave_do_servidor("127.0.0.1", servidor)
    with pytest.raises(ErroConexao, match="Autenticacao recusada"):
        await cadastro.registrar(_perfil(servidor, chave), "errada")
    assert "novo-dev" not in config.carregar_perfis()
    assert credenciais.obter("novo-dev", "senha") is None


async def test_rota_da_url_vira_pasta_inicial(servidor, repositorio, remoto, ops):
    (remoto / "logs" / "a.txt").write_text("x")
    chave = await chave_do_servidor("127.0.0.1", servidor)
    await cadastro.registrar(_perfil(servidor, chave, f"sftp://127.0.0.1:{servidor}/logs"), SENHA, str(repositorio))
    resultado = await ops.listar("novo-dev")
    assert resultado["caminho"] == "/logs" and [e["nome"] for e in resultado["entradas"]] == ["a.txt"]


async def test_cadastro_nao_toca_perfil_existente(perfil, servidor):
    """O perfil pode surgir enquanto a confirmacao da chave esta aberta."""
    chave = await chave_do_servidor("127.0.0.1", servidor)
    with pytest.raises(ErroOperacao, match="ja existe"):
        await cadastro.registrar(_perfil(servidor, chave, nome=perfil.nome), SENHA)
    assert config.obter_perfil(perfil.nome).raizes_escrita == ["/escrita"]
    with pytest.raises(ErroConexao):
        await cadastro.registrar(_perfil(servidor, chave, nome=perfil.nome), "errada")
    assert credenciais.obter(perfil.nome, "senha") == SENHA


async def test_falha_no_repositorio_nao_deixa_nada_gravado(servidor, repositorio):
    (repositorio / ".claude").write_text("arquivo no lugar da pasta")
    chave = await chave_do_servidor("127.0.0.1", servidor)
    with pytest.raises(OSError):
        await cadastro.registrar(_perfil(servidor, chave), SENHA, str(repositorio))
    assert "novo-dev" not in config.carregar_perfis()
    assert credenciais.obter("novo-dev", "senha") is None


async def test_login_nao_grava_a_senha_antes_de_terminar(servidor, monkeypatch):
    gravacoes = []
    monkeypatch.setattr(credenciais, "gravar", lambda *a: gravacoes.append(a))
    chave = await chave_do_servidor("127.0.0.1", servidor)
    with pytest.raises(ErroConexao):
        await cadastro.registrar(_perfil(servidor, chave), "errada")
    assert gravacoes == []


async def test_rota_que_e_arquivo_nao_grava(servidor, remoto):
    (remoto / "logs" / "a.txt").write_text("x")
    chave = await chave_do_servidor("127.0.0.1", servidor)
    with pytest.raises(ErroConexao, match="nao e pasta"):
        await cadastro.registrar(_perfil(servidor, chave, f"sftp://127.0.0.1:{servidor}/logs/a.txt"), SENHA)


async def test_rota_inexistente_nao_grava(servidor):
    chave = await chave_do_servidor("127.0.0.1", servidor)
    with pytest.raises(ErroConexao):
        await cadastro.registrar(_perfil(servidor, chave, f"sftp://127.0.0.1:{servidor}/nao-existe"), SENHA)
    assert "novo-dev" not in config.carregar_perfis()


def test_erro_repositorio(tmp_path):
    assert cadastro.erro_repositorio("") is None
    assert "nao existe" in cadastro.erro_repositorio(str(tmp_path / "nao-existe"))
    assert "nao e repositorio git" in cadastro.erro_repositorio(str(tmp_path))
