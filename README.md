# sftp-mcp

Servidor MCP para acessar, pelo Claude Code, o SFTP do TCloud, da TOTVS. Foi pensado para esse acesso: as conexões que você já tem no FileZilla viram perfis, e o resto já vem pronto. A leitura é livre. Toda escrita pede a sua aprovação, inclusive com `--dangerously-skip-permissions`.

**Nesta versão, os perfis vêm do FileZilla.** Toda conexão SFTP salva no FileZilla vira um perfil, relido a cada chamada: host, porta, usuário, senha e a chave do servidor que você aceitou lá. Não há janela de cadastro no MCP. O `perfis.toml` guarda só os ajustes de cada perfil (repositório do cliente, raízes, limites). Detalhes em [Perfis do FileZilla](#perfis-do-filezilla).

## O que ele faz

| Tool | Tipo | O que faz |
|---|---|---|
| `sftp_perfis` | leitura | Lista os perfis cadastrados, sem segredo |
| `sftp_listar` | leitura | Lista uma pasta: filtro glob, ordem por nome, data ou tamanho, até 200 itens por padrão |
| `sftp_info` | leitura | Tipo, tamanho, datas e permissões |
| `sftp_ler` | leitura | Lê texto por faixa de linhas, até o limite do perfil (padrão 1 MB) |
| `sftp_ultimas_linhas` | leitura | Final de log sem ler o arquivo inteiro |
| `sftp_buscar` | leitura | Busca por nome, até a profundidade do perfil (padrão 5); para em 60 s e devolve o que achou |
| `sftp_baixar` | leitura | Copia um arquivo, ou uma pasta inteira (com filtro) num lote com manifesto, para a pasta local do perfil |
| `sftp_enviar` | **escrita** | Envia arquivo local; sobrescrever exige `sobrescrever=true` e faz backup antes |
| `sftp_enviar_lote` | **escrita** | Envia até 100 arquivos para uma pasta numa aprovação só; confere todos os destinos antes do primeiro |
| `sftp_criar_pasta` | **escrita** | Cria pasta |
| `sftp_renomear` | **escrita** | Renomeia ou move, sem nunca sobrescrever |
| `sftp_vincular_repositorio` | **escrita** | Define o repositório local do cliente |

Não existe tool de apagar.

## Travas

- **Aprovação em toda escrita.** As tools de escrita declaram `_meta["anthropic/requiresUserInteraction"]: true`, e o Claude Code mostra o prompt de permissão em toda chamada, sem "não perguntar de novo". Isso vem no código: não precisa configurar nada, e foi testado com `--dangerously-skip-permissions`, sem nenhuma regra no `settings.json`.
- **Só o Claude Code garante esse prompt.** A marca `requiresUserInteraction` é dele, e o servidor não confere se houve aprovação. Em outro cliente MCP, use `raizes_escrita` e não conte com a confirmação.
- **Raízes de escrita (opcional).** Por padrão a escrita vale em qualquer pasta que o usuário SFTP alcance, sempre com aprovação. Para limitar, declare `raizes_escrita` no perfil. O caminho é resolvido pelo servidor (`realpath`) antes da checagem, então `..` e symlink não saem da raiz. Escrever sobre um symlink é recusado em qualquer caso.
- **Host key fixada.** A chave pública do servidor é gravada no cadastro. Chave nova pede a sua confirmação; chave já aceita em outro perfil entra direto, porque vários ambientes do TCloud ficam atrás do mesmo gateway. Se o servidor apresentar outra depois, a conexão é recusada. O `~/.ssh/known_hosts`, o `~/.ssh/config` e o agente SSH não são usados.
- **Segredo fora do modelo.** Em perfil do FileZilla, a senha é lida do arquivo do FileZilla só na hora de conectar. Em perfil próprio, ela é digitada no `sftp-mcp-setup` e vai direto para o keyring do sistema (Credential Manager no Windows). Nos dois casos ela nunca é parâmetro de tool e não volta na resposta.
- **Envio sem arquivo pela metade.** O arquivo vai para um temporário oculto na mesma pasta e só no fim troca o destino (`posix-rename`). Se a conexão cair, o destino continua como estava.
- **Tudo auditado.** Cada operação gera uma linha JSON em `audit.log`, sem conteúdo de arquivo e sem segredo.

## Pasta local do cliente

Cada perfil aponta para o repositório git do cliente na sua máquina. Downloads, backups e auditoria ficam em:

```
<repositório>/.claude/sftp/<perfil>/
├── downloads/   arquivo avulso espelha o caminho remoto; pasta vira um lote em <data-hora>/ com manifesto.json
├── backups/     <data-hora>/<caminho remoto>, versão anterior de cada arquivo sobrescrito
└── audit.log
```

A pasta `.claude/` não pode entrar no git do cliente. Ao vincular, o servidor roda `git check-ignore` e avisa se ela não estiver ignorada.

Sem repositório vinculado, ler, listar e buscar funcionam, com a auditoria em `~/.sftp-mcp/auditoria/<perfil>/`. Baixar e escrever falham pedindo que o agente pergunte a pasta a você e chame `sftp_vincular_repositorio`.

## Instalação

Requer Python 3.11 ou superior.

```powershell
git clone https://github.com/guipegoraro/sftp-mcp
cd sftp-mcp
pip install -e .
```

Registre no Claude Code (escopo de usuário):

```powershell
claude mcp add -s user sftp -- python -P -m sftp_mcp
```

A aprovação de escrita já vem ativa, sem configuração no `settings.json`.

## Perfis do FileZilla

O MCP lê, a cada chamada, a pasta do FileZilla (`%APPDATA%\FileZilla`, ou a de `FILEZILLA_HOME`):

| Arquivo | O que sai dele |
|---|---|
| `sitemanager.xml` | Sites do Gerenciador de Sites. Têm prioridade, e o nome do site vira o nome do perfil (`Cliente X Produção` → `cliente-x-producao`) |
| `recentservers.xml` | Servidores recentes. O nome do perfil é o começo do host mais o ambiente (`clientex123456-prod`) |
| `hostkeys.xml` | Chave do servidor que você aceitou no FileZilla. Sem ela o perfil fica indisponível |

- Só entram conexões SFTP com senha salva ou arquivo de chave (OpenSSH, não `.ppk`). O ambiente sai do usuário do TCloud (`ftp_XXXXXX_production` vira `prod`) e pode ser trocado no `perfis.toml`.
- Ambiente novo, senha trocada ou chave do servidor trocada: conecte pelo FileZilla e salve lá. O MCP vê a mudança na chamada seguinte.
- **Salve as conexões no Gerenciador de Sites.** A lista de recentes do FileZilla é curta: um servidor que sai dela some dos perfis, e os ajustes dele no `perfis.toml` ficam guardados até ele voltar.
- **Senha mestra do FileZilla não é lida.** Com ela ligada, a senha cai para o Credential Manager: `sftp-mcp-setup definir-senha <perfil>`.
- `sftp_perfis` e `sftp-mcp-setup listar` mostram as conexões que não viraram perfil, com o motivo.
- Host, porta, usuário, chave e autenticação de perfil do FileZilla não podem ficar no `perfis.toml`: altere no FileZilla.
- Os ajustes gravados levam `conexao = "usuario@host:porta"`. Renomear o site, ou salvar no Gerenciador de Sites uma conexão que estava nos recentes, mantém os ajustes: o perfil com o nome novo herda os da mesma conexão. A pasta local passa a ser `.claude/sftp/<nome novo>/`.
- Se um nome passar a apontar para outra conexão, o perfil fica indisponível em vez de herdar repositório e raízes. Sendo a mesma conexão, rode `sftp-mcp-setup remover <perfil>` e vincule de novo.

## Perfis próprios (sem FileZilla)

Para um servidor fora do FileZilla, cadastre pelo terminal com `sftp-mcp-setup adicionar <perfil>`. A senha vai para o Credential Manager e a chave do servidor fica fixada no `perfis.toml`. Informe:

- **URL**, como o TCloud mostra: `sftp://host:porta`, com a rota no final se houver (`sftp://host:porta/pasta`). A rota vira a pasta inicial do perfil.
- **Usuário** e **senha**.
- **Ambiente**: vem deduzido do usuário (`ftp_XXXXXX_development` vira `dev`), e dá para trocar.

O cadastro testa o login e só então grava. Senha errada não deixa nada gravado. Os demais comandos:

```powershell
sftp-mcp-setup adicionar cliente-prod
sftp-mcp-setup listar
sftp-mcp-setup testar cliente-prod
sftp-mcp-setup definir-senha cliente-prod
sftp-mcp-setup trocar-fingerprint cliente-prod
sftp-mcp-setup vincular-repositorio cliente-prod C:\caminho\do\repo
sftp-mcp-setup remover cliente-prod
```

Os perfis ficam em `~/.sftp-mcp/perfis.toml` (ou na pasta de `SFTP_MCP_HOME`). Dá para editar à mão:

```toml
[perfis.cliente-prod]
host = "cliente123456.protheus.cloudtotvs.com.br"
porta = 10501
usuario = "ftp_XXXXXX_production"
host_key = "ssh-ed25519 AAAA..."
autenticacao = "senha"          # ou "chave", com chave_privada = "C:\\caminho\\id_ed25519"
chave_privada = ""
ambiente = "prod"               # prod, hml ou dev
tspace_cliente = ""
repositorio = "C:\\caminho\\do\\repo"
pasta_inicial = ""              # rota da URL; caminhos relativos partem dela
raizes_leitura = []             # vazio = servidor inteiro
raizes_escrita = []             # vazio = qualquer pasta, sempre com aprovacao
timeout_conexao = 15
ocioso_max_segundos = 300
max_leitura_bytes = 1048576
busca_profundidade = 5
busca_max_resultados = 2000
```

Chave privada no formato PuTTY (`.ppk`) não é aceita. No PuTTYgen: *Load*, depois *Conversions > Export OpenSSH key*.

## Testes

```powershell
pip install -e .[teste]
python -m pytest
```

Os testes sobem um servidor SFTP do `asyncssh` no próprio processo e usam um keyring em memória. Eles não acessam servidor real.

## Limites conhecidos

- Só SFTP. FTP e FTPS não são suportados.
- Download de pasta: até 500 arquivos e 500 MB por lote; acima disso recusa sem baixar nada. Envio em lote: até 100 arquivos.
- Nome de arquivo com byte que não é UTF-8 (comum no spool do Protheus) aparece como `\xHH` (`t\xE3\xADtulos.xml`). Repetir o caminho assim chega ao arquivo; outra barra invertida continua recusada.
- A cifra `chacha20-poly1305` fica fora da proposta do cliente: com ela, o gateway `SSH-2.0-Pandora` do TCloud derruba o login com "Max packet size exceeded". AES-GCM e AES-CTR continuam.
- Sem jump host. VPN fica por sua conta.
- Quem roda código como o seu usuário do Windows lê o Credential Manager. Veja [SECURITY.md](SECURITY.md).
