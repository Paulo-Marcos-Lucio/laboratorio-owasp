# Changelog

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado

- A10 SSRF (CWE-918): par vulnerável/corrigido em `a10ssrf`. O `/vulneravel` busca
  qualquer URL recebida do usuário, então `?url=http://127.0.0.1:.../interno` ou
  `?url=http://169.254.169.254/...` faz o servidor alcançar serviços internos e o endpoint
  de metadados de nuvem. O `/corrigido` aplica duas camadas: allowlist de host + só
  esquemas `http`/`https`; e, como defesa em profundidade, resolve o host e recusa qualquer
  endereço interno (loopback, `0.0.0.0`, link-local 169.254/16, privado 10/8, 172.16/12,
  192.168/16, multicast e unique-local IPv6 fc00::/7).
- `SsrfTest` + `SsrfDefesaIpTest` + `SsrfAllowlistTest` + `SsrfValidacaoTest` (10 casos):
  o exploit sobe um servidor HTTP de loopback (sem rede externa) e o lado vulnerável vaza
  o segredo interno; o corrigido bloqueia loopback, host fora da allowlist e esquema não
  http; a camada de IP barra loopback/metadados/privado mesmo quando o host está na
  allowlist; um host permitido com endereço público é aceito (sem falso positivo); e a
  classificação de endereço interno é testada nos dois sentidos.
- A03 Command Injection (CWE-78): par vulnerável/corrigido em `a03cmd`. O
  `/vulneravel` concatena o host recebido numa linha de comando e a entrega a um shell
  (`sh -c` / `cmd /c`), então `127.0.0.1 && echo INJETADO` roda um segundo comando; o
  `/corrigido` nunca entrega a entrada a um shell — valida o host contra uma allowlist
  estrita (`[A-Za-z0-9._-]`) e recusa qualquer metacaractere.
- `CommandInjectionTest` com 5 casos: o exploit executa de fato um segundo comando no
  lado vulnerável (a saída traz o marcador, não o literal `echo`), e o corrigido bloqueia
  `&&`, `;` e substituição de comando `$(...)`, preservando um hostname legítimo.
- A01 Open Redirect (CWE-601): par vulnerável/corrigido em `a01redirect`. O
  `/vulneravel` redireciona para qualquer destino recebido; o `/corrigido` só aceita
  caminhos relativos ao próprio app, recusando URLs absolutas e as variações
  protocolo-relativas (`//host`, `/\host`) que o navegador trata como externas.
- `OpenRedirectTest` com 5 casos: exploit externo no lado vulnerável, bloqueio de
  destino externo, protocolo-relativo e truque de barra invertida no corrigido, e
  redirect interno legítimo preservado.

## [0.1.0] — 2026-07-21

### Adicionado

- Aplicação Spring Boot 3.3 (Java 21) com 5 vulnerabilidades do OWASP Top 10,
  cada uma em par vulnerável/corrigido:
  - A03 SQL Injection (concatenação → consulta parametrizada);
  - A03 XSS refletido (reflexão crua → codificação de saída);
  - A01 IDOR (sem verificação → autorização por propriedade);
  - A01 Path Traversal (resolve direto → normalização + confinamento);
  - A02 hash de senha (MD5 sem sal → BCrypt).
- 14 testes JUnit que provam o exploit no lado vulnerável e o bloqueio no corrigido.
- Maven wrapper, CI (GitHub Actions com actions fixadas por SHA).
