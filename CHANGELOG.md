# Changelog

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado

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
