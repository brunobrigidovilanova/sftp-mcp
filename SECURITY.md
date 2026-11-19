# Modelo de ameaças

## O que está protegido

| Ativo | Onde fica | Proteção |
|---|---|---|
| Senha ou passphrase | Keyring do sistema (serviço `sftp-mcp`, usuário `<perfil>:senha`) | DPAPI por usuário no Windows. Nunca vai para arquivo, parâmetro de tool, log ou mensagem de erro |
| Identidade do servidor | `host_key` no `perfis.toml` | Chave divergente recusa a conexão antes de enviar a senha |
| Senha de perfil do FileZilla | `sitemanager.xml` / `recentservers.xml` do FileZilla, em base64 | Só a do `$HOME`: o FileZilla grava assim. O MCP decodifica na hora de conectar e nunca devolve, loga nem grava |
| Identidade de perfil do FileZilla | `hostkeys.xml` do FileZilla | A chave que você aceitou no FileZilla vale como fixada. Sem chave aceita, o perfil não é usado |
| Arquivos do cliente | `<repositório>/.claude/sftp/<perfil>/` | Fora do git do cliente; o vínculo avisa se a pasta não estiver ignorada. Leitura sem repositório só audita, em `~/.sftp-mcp/auditoria/<perfil>/`, sem conteúdo |
| Servidor do cliente | Escrita | Prompt de aprovação em toda chamada, sem apagar, com backup antes de sobrescrever. `raizes_escrita` limita as pastas, se declarada |

## Contra o próprio agente

O risco principal é o modelo escrever no servidor do cliente sem você querer, por engano ou induzido por conteúdo lido (log, `.ini`, arquivo de terceiro).

- As tools de escrita declaram `anthropic/requiresUserInteraction`. O Claude Code pede confirmação em toda chamada, sem depender de configuração. Testado com `--dangerously-skip-permissions` e sem regra no `settings.json`.
- O prompt mostra os parâmetros da chamada. Caminho com caractere de controle ou invisível (bidi, zero-width) é recusado, para o destino exibido ser o destino real.
- `sftp_enviar` e `sftp_enviar_lote` só enviam arquivo que já existe no disco local, e os caminhos aparecem no prompt (o lote mostra a lista inteira numa aprovação).
- A senha nunca passa pelo modelo. Em perfil do FileZilla, o servidor MCP a lê do arquivo do FileZilla só para conectar. Em perfil próprio, ela é digitada no `sftp-mcp-setup`, fora do MCP.
- Os ajustes de um perfil do FileZilla no `perfis.toml` (repositório, raízes) guardam a conexão a que pertencem (`conexao = "usuario@host:porta"`). Renomear o site na mesma conexão mantém os ajustes; se o nome passar a outra conexão, o perfil fica indisponível em vez de herdar repositório e raízes. A senha reserva no Credential Manager também fica pela conexão, e nome repetido no FileZilla tira todas as conexões com aquele nome.
- O servidor não executa comando remoto. Só operações SFTP.

## O que NÃO está protegido

- **A aprovação depende do cliente MCP.** O prompt vem do Claude Code, por causa da marca `requiresUserInteraction`. O servidor não confere se houve aprovação: outro cliente que ignore a marca escreve sem perguntar. Nesse caso, a única trava é `raizes_escrita`, se declarada.
- **Escrita pelo shell.** O MCP só controla as próprias tools. Se o agente tiver acesso ao shell, ele pode rodar `sftp`, `curl` ou importar este pacote num script, e nada aqui impede. Com `--dangerously-skip-permissions`, isso acontece sem prompt.
- **Senha do FileZilla em base64 no disco.** Qualquer processo com o seu usuário lê. É o formato do próprio FileZilla sem senha mestra; com senha mestra, o MCP não lê e usa o Credential Manager.
- **Quem altera os XML do FileZilla** troca a chave aceita ou o servidor de um perfil. Exige o mesmo acesso que alterar o `perfis.toml`.
- **Código malicioso rodando como o seu usuário do Windows** lê o Credential Manager, altera o `perfis.toml` (inclusive `raizes_escrita` e `host_key`) e importa este pacote para escrever sem aprovação.
- **Chave de host reaproveitada.** Chave já aceita em outro perfil entra sem confirmação no cadastro. Um servidor diferente que apresente a mesma chave precisaria ter a chave privada dela.
- **Corrida entre checagem e escrita (TOCTOU).** Entre o `realpath` e a escrita, alguém com acesso ao servidor pode trocar uma pasta por symlink. Exige um atacante já dentro do servidor do cliente.
- **Envio interrompido** pode deixar um temporário oculto `.<nome>.sftp-mcp-<hex>.tmp` na pasta remota quando a conexão cai antes da limpeza. O destino não é tocado. Em servidor sem `posix-rename`, a troca apaga o destino e renomeia o temporário, e nesse intervalo curto o arquivo não existe; a versão anterior está em `backups/`.
- **Leitura do servidor inteiro** quando `raizes_leitura` está vazio. É a configuração padrão, porque o usuário SFTP do cliente costuma já ser restrito.
- **Downloads e backups** ficam em texto puro no disco, com a proteção do `$HOME` e do repositório.
