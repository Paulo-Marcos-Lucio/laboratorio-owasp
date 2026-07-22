<div align="center">

# 🧪 Laboratório OWASP

### Cada vulnerabilidade do OWASP Top 10 em **três atos**: vulnerável → exploit → corrigido.

*Uma aplicação **Spring Boot** onde cada falha vive em dois endpoints — `/vulneravel` e `/corrigido` — e um **teste automatizado prova** que o exploit funciona na versão vulnerável e é bloqueado na corrigida. É o "diagnóstico e correção" em código executável, no stack Java.*

[![CI](https://github.com/Paulo-Marcos-Lucio/laboratorio-owasp/actions/workflows/ci.yml/badge.svg)](https://github.com/Paulo-Marcos-Lucio/laboratorio-owasp/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top_10-000000.svg)](https://owasp.org/Top10/)

</div>

---

## ⚠️ Aviso

Esta aplicação contém vulnerabilidades **de propósito**, para fins educativos. **Não a exponha na internet.** Rode localmente.

---

## 🎯 A ideia

Ler sobre uma vulnerabilidade é uma coisa; **ver o exploit passar** e depois **ver a correção barrá-lo** é outra. Cada módulo aqui é um par:

- `…/vulneravel` — a implementação insegura, com o comentário explicando o erro.
- `…/corrigido` — a mesma funcionalidade, feita com segurança.
- um **teste** que dispara o exploit real e afirma o comportamento dos dois lados.

Se os testes passam, a demonstração é honesta: a falha é real e a correção funciona.

---

## 🗂️ As vulnerabilidades

| OWASP | Vulnerabilidade | Onde | Teste que prova |
| --- | --- | --- | --- |
| **A03** | SQL Injection (CWE-89) | [`a03sqli`](src/main/java/br/com/paulomarcos/labowasp/a03sqli) | [`SqlInjectionTest`](src/test/java/br/com/paulomarcos/labowasp/SqlInjectionTest.java) |
| **A03** | XSS refletido (CWE-79) | [`a03xss`](src/main/java/br/com/paulomarcos/labowasp/a03xss) | [`XssTest`](src/test/java/br/com/paulomarcos/labowasp/XssTest.java) |
| **A01** | IDOR — Broken Access Control (CWE-639) | [`a01idor`](src/main/java/br/com/paulomarcos/labowasp/a01idor) | [`IdorTest`](src/test/java/br/com/paulomarcos/labowasp/IdorTest.java) |
| **A01** | Path Traversal (CWE-22) | [`a01path`](src/main/java/br/com/paulomarcos/labowasp/a01path) | [`ArquivoServiceTest`](src/test/java/br/com/paulomarcos/labowasp/ArquivoServiceTest.java) |
| **A02** | Hash de senha fraco: MD5 → BCrypt (CWE-916) | [`a02crypto`](src/main/java/br/com/paulomarcos/labowasp/a02crypto) | [`HashSenhaTest`](src/test/java/br/com/paulomarcos/labowasp/HashSenhaTest.java) |

---

## 🚀 Rodando

Requer **Java 21+**. (Ou use Docker: `docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-21 mvn test`.)

```bash
./mvnw spring-boot:run     # ou: mvn spring-boot:run
```

### Veja o exploit e a correção lado a lado

```bash
# A03 — SQL Injection: o payload retorna a tabela inteira...
curl "http://localhost:8080/a03/sqli/vulneravel?nome=Notebook' OR '1'='1"
# ...e a versão parametrizada retorna vazio:
curl "http://localhost:8080/a03/sqli/corrigido?nome=Notebook' OR '1'='1"

# A03 — XSS: o <script> volta cru (vulnerável) vs. escapado (corrigido)
curl "http://localhost:8080/a03/xss/vulneravel?q=<script>alert(1)</script>"
curl "http://localhost:8080/a03/xss/corrigido?q=<script>alert(1)</script>"

# A01 — IDOR: bob lê a nota da alice (vulnerável) vs. 403 (corrigido)
curl -H "X-Usuario: bob" http://localhost:8080/a01/idor/vulneravel/1
curl -i -H "X-Usuario: bob" http://localhost:8080/a01/idor/corrigido/1
```

### Rodando os testes (a prova)

```bash
mvn test
```

---

## 🏗️ Como está organizado

```
src/main/java/.../labowasp/
├── a01idor/    IDOR — verificação de propriedade do recurso
├── a01path/    Path Traversal — normalização + confinamento ao diretório-base
├── a02crypto/  Hash de senha — MD5 (errado) vs BCrypt (certo)
├── a03sqli/    SQL Injection — concatenação vs consulta parametrizada
└── a03xss/     XSS — reflexão crua vs codificação de saída
```

Cada correção aplica **o princípio certo**, não um remendo: parametrização de consulta, codificação de saída, autorização baseada em propriedade, confinamento de caminho e hashing lento com sal.

---

## ⚖️ Uso ético

Material **didático e defensivo**. As técnicas de exploração servem para entender e corrigir a falha — use apenas neste laboratório ou em sistemas que você tem autorização para testar.

---

## 📄 Licença

[MIT](LICENSE) © 2026 Paulo Marcos Lucio.

---

<div align="center">
<sub>Parte da suíte AppSec — junto do <a href="https://github.com/Paulo-Marcos-Lucio/sentinela">Sentinela</a>, <a href="https://github.com/Paulo-Marcos-Lucio/guardiao">Guardião</a>, <a href="https://github.com/Paulo-Marcos-Lucio/chaveiro">Chaveiro</a> e <a href="https://github.com/Paulo-Marcos-Lucio/esteira">Esteira</a>.</sub>
</div>
