# Política de Segurança

Este repositório é um **laboratório didático** e contém vulnerabilidades de propósito. Não é um produto — não o exponha na internet.

A aplicação escuta apenas em `127.0.0.1` (`server.address` em `src/main/resources/application.properties`, com teste de regressão em `ConfiguracaoDeRedeTest`). Isso é intencional e não deve ser alterado: `/a05/cmd/vulneravel` executa comandos arbitrários do sistema operacional sem nenhuma autenticação.

## O que reportar

Está **dentro** do escopo: qualquer problema **fora do escopo educativo** — configuração de build, do CI ou do wrapper Maven; um lado `/corrigido` que não corrige de fato; um texto que promete uma defesa que o código não tem; uma vulnerabilidade que escapa do laboratório e ameaça a máquina de quem estuda.

Está **fora** do escopo: as vulnerabilidades dos endpoints `/vulneravel`. Elas são a razão de o repositório existir e estão documentadas no README.

Reporte de forma privada para **pmlsp23@gmail.com** com o prefixo `[security]`. Resposta em até 5 dias úteis.

## Enquadramento legal (Brasil)

As técnicas demonstradas aqui só podem ser usadas neste laboratório ou em sistema para o qual você tenha **autorização por escrito**, com escopo e janela definidos.

- **Lei 12.737/2012** (Lei Carolina Dieckmann) — tipifica a invasão de dispositivo informático alheio.
- **Lei 14.155/2021** — amplia as penas dos crimes cometidos por meio eletrônico.
- **Lei 12.965/2014** (Marco Civil da Internet) — deveres de guarda e de sigilo de registros e comunicações.
- **Lei 13.709/2018** (LGPD) — trata do que você faz com qualquer dado pessoal alcançado durante um teste.

Autorização verbal não protege ninguém. Sem contrato ou ordem de serviço assinada, não teste.
