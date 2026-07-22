# Contribuindo

Novas demonstrações de vulnerabilidade são bem-vindas.

## Rodar

```bash
./mvnw test          # roda todos os testes (exploit vs correção)
./mvnw spring-boot:run
```

## Adicionar uma vulnerabilidade

Cada módulo segue o mesmo padrão:

1. Um pacote por vulnerabilidade (ex.: `a05config`).
2. Endpoints (ou serviço) `vulneravel` **e** `corrigido`, com um comentário explicando o erro e o princípio da correção.
3. Um teste que **dispara o exploit real** e afirma o comportamento dos dois lados — a demonstração só vale se o teste prova a diferença.
4. Uma linha na tabela do `README.md`.
