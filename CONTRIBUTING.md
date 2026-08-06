<p align="center"><a href="CONTRIBUTING.en.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/laboratorio-owasp/main/assets/btn-lang-en.svg" alt="Read this document in English" width="300"/></a></p>

# Contribuindo

Novas demonstrações de vulnerabilidade são bem-vindas — em especial as sete categorias do OWASP Top 10:2025 que ainda não têm par (A02, A03, A06, A07, A08, A09 e A10).

## Rodar

```bash
./mvnw verify            # formatação (spotless) + todos os testes
./mvnw spotless:apply    # conserta a formatação (google-java-format, perfil AOSP)
./mvnw spring-boot:run
```

O `verify` é o mesmo comando que o CI roda. Se ele passa aqui, passa lá.

## Adicionar uma vulnerabilidade

Cada módulo segue o mesmo padrão:

1. Um pacote por vulnerabilidade, nomeado pelo **código do OWASP Top 10:2025** mais um sufixo curto (ex.: `a02config` para Security Misconfiguration).
2. Endpoints (ou serviço) `vulneravel` **e** `corrigido`, com um comentário explicando o erro e o princípio da correção.
3. Um teste que **dispara o exploit real** e afirma o comportamento dos dois lados, no pacote de teste **espelhado** (`src/test/java/.../a02config/`).
4. Uma linha na tabela do `README.md` e uma entrada no `CHANGELOG.md`.

## O teste precisa falhar quando a correção sumir

Este é o critério que decide se um PR entra. Apague o controle de segurança que você acabou de escrever, rode `./mvnw test` e confira que o teste fica **vermelho**. Se ele continuar verde, ele não está testando o controle — está testando outra coisa (um DNS que não resolve, uma guarda anterior, um erro genérico). Aconteceu neste repositório: dois testes de SSRF passavam com a allowlist inteira deletada.

Assertar o **motivo** da recusa (`content().string("host fora da allowlist")`), e não só o status, mata a maior parte dessa classe de falso-verde.

## Limite conhecido também é conteúdo

Se a correção só resolve parte do problema, escreva isso no javadoc e, se der, num teste que **documente o limite** — como o `SsrfLimiteRebindingTest`. Prometer uma defesa que o código não tem é o pior defeito possível num material didático.
