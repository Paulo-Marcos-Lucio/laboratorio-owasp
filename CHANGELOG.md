# Changelog

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Corrigido

- **A aplicação escutava em `0.0.0.0`** (padrão do Spring Boot), expondo
  `/a05/cmd/vulneravel` — execução de comando arbitrária, sem autenticação — para
  qualquer máquina da mesma rede. Medido antes da correção: `netstat` mostrava
  `0.0.0.0:8080` e `[::]:8080`, e um `whoami` injetado respondia pelos IPs de LAN, WSL e
  da VPN de malha. Agora `server.address=127.0.0.1`, verificado: só
  `127.0.0.1:8080 LISTENING`, e os três IPs externos dão conexão recusada. `ConfiguracaoDeRedeTest`
  reprova o build se a linha sumir. Nenhum exemplo do README mudou — todos já usavam `localhost`.
- **O lado `corrigido` da lição de senha autenticava a senha ERRADA.** O
  `spring-boot-starter-parent` estava em 3.3.4 (set/2024), que traz
  spring-security-crypto 6.3.3, afetado pela CVE-2025-22228: o `BCryptPasswordEncoder`
  truncava a senha em 72 bytes no `encode` e o `matches` depois devolvia `true` para
  qualquer senha errada que compartilhasse esses 72 bytes. O parent subiu para 3.5.7
  (spring-security 6.5.6, que recusa a senha longa) e `HashSenhaTest` ganhou o caso que
  falha em qualquer versão vulnerável.
- **O `timeout` de 10 s do executor de comandos era decorativo.** A saída era lida com
  `readAllBytes()` antes do `waitFor(10, SECONDS)`, e `readAllBytes` só retorna no EOF do
  stdout do filho — o limite nunca podia disparar. Medido: uma requisição com
  `&& ping -n 20` prendia uma thread do Tomcat por 19,3 s. Agora a saída vai para um
  arquivo temporário, o `waitFor` é o único ponto de bloqueio e o processo (com seus
  descendentes) é morto ao estourar o limite. Com limite de 1 s, o executor volta em ~1 s
  contra 29,3 s da versão anterior.
- **O Open Redirect `corrigido` recusava `/`** — a raiz, o destino pós-login mais comum —
  por causa da guarda `length() < 2`, e devolvia **500** para qualquer destino que não
  fosse um URI válido (`/meu painel`). Agora `/` redireciona (302) e entrada malformada
  responde 400, nos dois endpoints.
- **O `/vulneravel` do SSRF devolvia 500 opaco** quando o destino não respondia (o caso do
  IP de metadados fora de uma nuvem — exatamente o exemplo do README). Agora responde 502
  com o motivo. O SSRF continua inteiro: o que mudou foi o erro deixar de esconder a lição.

### Alterado

- **Migração para o OWASP Top 10:2025**, acompanhando o resto da suíte. Os pacotes e as
  rotas seguem o código atual: `a03sqli`/`a03xss`/`a03cmd` → `a05*` (A03:2021 Injection
  virou A05:2025), `a02crypto` → `a04crypto` (A02:2021 Cryptographic Failures virou
  A04:2025) e `a10ssrf` → `a01ssrf` (A10:2021 SSRF foi absorvido por A01:2025 Broken
  Access Control). As rotas `/a03/*` e `/a10/*` passam a ser `/a05/*` e `/a01/*`.
- **O javadoc do SSRF `/corrigido` parou de prometer proteção contra DNS rebinding**, que
  ele não tem: a validação e a busca resolvem o host de forma independente e o endereço já
  validado é descartado (TOCTOU). O texto agora descreve o escopo real da camada 2
  (split-horizon, allowlist mal configurada) e cita a mitigação de verdade.
- Cada classe de teste passou para o pacote espelhado do código que ela exercita
  (`a01idor`, `a01path`, `a01redirect`, `a01ssrf`, `a04crypto`, `a05cmd`, `a05sqli`,
  `a05xss`), deixando a lição inteira — vulnerável, corrigido e prova — na mesma pasta.
- README honesto quanto à cobertura: **3 das 10** categorias de 2025 (A01, A04 e A05),
  descritas por categoria em vez de um número frágil de vulnerabilidades, com **49 testes
  verdes** provando exploit e correção, os dois pares sem endpoint HTTP marcados como tais,
  e uma seção "O que este laboratório NÃO faz".
- Os comandos `curl` do README foram reescritos com `curl -G --data-urlencode` e a saída
  esperada de cada um. Antes, 4 dos 6 exemplos falhavam quando copiados e colados (o curl
  recusava a URL com espaço; o Tomcat rejeitava `<` e `>` crus com 400).

### Adicionado

- `SsrfLimiteRebindingTest`: prova executável de que a camada de IP **não** impede DNS
  rebinding. Um `InetAddressResolverProvider` de teste devolve um IP público na primeira
  consulta e o loopback nas seguintes; o `/corrigido` aprova e vaza o segredo com HTTP 200.
  Documenta o limite em vez de escondê-lo.
- `HttpBuscadorTest`: os dois controles do buscador (`Redirect.NEVER` e o corte de corpo em
  8192 bytes) estavam afirmados no javadoc e não tinham teste — dava para trocar por
  `Redirect.ALWAYS` e `Integer.MAX_VALUE` com a suíte inteira verde.
- `ExecucaoComLimiteDeTempoTest` e `ConfiguracaoDeRedeTest` (ver "Corrigido").
- `HashSenhaTest` ganhou o portão da CVE-2025-22228 e um teste que documenta o limite de
  72 bytes do BCrypt, com a saída de qual KDF usar para passphrases longas.
- Portão de formatação: `spotless-maven-plugin` com google-java-format (perfil AOSP),
  ligado ao `verify`. O CI passou de `./mvnw -B test` para `./mvnw -B verify`, e ganhou
  `concurrency`, `timeout-minutes` e `persist-credentials: false`.
- `.github/dependabot.yml` (Maven + GitHub Actions, mensal e agrupado). A ausência dele é a
  causa-raiz de a CVE-2025-22228 ter ficado dez meses no repositório sem ninguém saber.
- `SECURITY.md` com escopo do que reportar e o enquadramento legal brasileiro (Leis
  12.737/2012, 14.155/2021, 12.965/2014 e LGPD), alinhado ao resto da suíte.

### Removido

- `@Service` de `ArquivoService`: fiação morta. Ninguém injetava o bean, e a anotação
  sugeria uma injeção que não existe.

### Histórico desta seção (antes das correções acima)

- A10 SSRF (CWE-918): par vulnerável/corrigido, hoje em `a01ssrf`. O `/vulneravel` busca
  qualquer URL recebida do usuário, então `?url=http://127.0.0.1:.../interno` ou
  `?url=http://169.254.169.254/...` faz o servidor alcançar serviços internos e o endpoint
  de metadados de nuvem. O `/corrigido` aplica duas camadas: allowlist de host + só
  esquemas `http`/`https`; e, como defesa em profundidade, resolve o host e recusa qualquer
  endereço interno (loopback, `0.0.0.0`, link-local 169.254/16, privado 10/8, 172.16/12,
  192.168/16, multicast e unique-local IPv6 fc00::/7).
- `SsrfTest` + `SsrfDefesaIpTest` + `SsrfAllowlistTest` + `SsrfValidacaoTest`:
  o exploit sobe um servidor HTTP de loopback (sem rede externa) e o lado vulnerável vaza
  o segredo interno; o corrigido bloqueia loopback, host fora da allowlist e esquema não
  http; a camada de IP barra loopback/metadados/privado mesmo quando o host está na
  allowlist; um host permitido com endereço público é aceito (sem falso positivo); e a
  classificação de endereço interno é testada nos dois sentidos.
- A03 Command Injection (CWE-78): par vulnerável/corrigido, hoje em `a05cmd`. O
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
- `OpenRedirectTest`: exploit externo no lado vulnerável, bloqueio de destino externo,
  protocolo-relativo e truque de barra invertida no corrigido, e redirect interno legítimo
  preservado.

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
