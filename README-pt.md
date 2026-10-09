# Centro de Alertas Inteligente (`dsh-syslog-alert`)

Executa um receptor syslog UDP/TCP **dentro do DSH** e ingere cada alerta do dispositivo em
tempo real: parse → pré-filtro → deduplicação por impressão digital → limite por dispositivo →
registro de alerta → entrega à sessão de alertas do dia. Os alertas fluem no painel; clique em
uma linha para ver a cronologia completa daquele alerta.

**A análise é delegada ao agente da sessão.** O próprio plugin não faz nenhuma chamada de modelo:
o primeiro log do dia abre uma sessão ordinária, os logs seguintes são publicados nela, e o
agente os analisa e chama a ferramenta `syslog_conclude` para escrever a conclusão de volta no
detalhe do alerta.

> Versão em inglês: [README.md](./README.md). 中文说明见 [README-zh.md](./README-zh.md).

## Requirements

- DSH com `sessionController` disponível (integrado no host; a sessão de alertas do dia não
  precisa de provider nem de escolha de modelo)
- Node 22.19+ ou 24+ (o runtime incluído no DSH atende)

## Install

```bash
dsh plugin add /path/to/dsh-syslog-alert-0.1.0.tgz
```

Depois abra as configurações do plugin, defina as portas de escuta (UDP+TCP 1514 por padrão) e
aponte o encaminhador syslog do dispositivo para o endereço do host DSH.

## How it works

```
socket → parse → pre-filter → fingerprint dedup → per-device rate limit
       → alert record → day-session delivery → SSE
```

A rota de ingestão é totalmente síncrona e barata. Quatro freios independentes protegem contra
um flap que emite milhares de linhas: pré-filtro, deduplicação por impressão digital, limite por
dispositivo e por minuto, e agregação de tempestade. A análise não está na rota de ingestão —
ocorre na sessão de alertas do dia, feita pelo agente.

## Safety model

- O texto do log entra sempre no prompt dentro de uma valla marcada como **dados**, nunca misturada
  com instruções; a sessão do dia compartilha um mesmo neutralizador, de modo que uma valla de
  fechamento falsificada é reescrita e perde o efeito.
- O id do alerta, o nome do dispositivo e o log original são adicionados pelo próprio plugin; um
  prompt personalizado só pode substituir a linha de instrução, e nada do log pode deslocá-los.
- Um pacote cujo remetente não é um dispositivo mapeado segue a política de não mapeados: é
  guardado e sinalizado por padrão.
- Pacotes que não podem ser analisados com confiança são guardados e exibidos, sem serem usados
  como campos estruturados.

## Configuration

Pelo painel de configurações: portas e transportes, mapeamento de origens e a sessão de alertas do
dia (prefixo do título, workspace, prompt).

## Troubleshooting

| Sintoma | Causa e solução |
| --- | --- |
| Nenhum alerta chega | Verifique as **portas vinculadas**; uma falha de bind (ex.: a 514 exige elevação no Linux) é reportada como porta com falha, não ignorada. |
| O detalhe não mostra "当日会话分析结论" | A conclusão é escrita pelo agente da sessão ao chamar `syslog_conclude`. Após uma entrega correta o detalhe mostra primeiro "会话分析中"; se ficar parado, o agente não chamou a ferramenta, ou o alerta já saiu do anel em memória. |
| A sessão de alertas não foi criada | O estado do painel dá o motivo: o interruptor desligado (当日会话未启用), o host não oferece `sessionController`, ou o primeiro log do dia ainda não chegou. `GET /syslog-api/auto-session` mostra o mesmo estado. |
| A sessão abriu em um workspace errado | Um workspace que não é caminho absoluto é ignorado (o `cwd` do DSH só aceita caminhos absolutos); o plugin volta ao workspace atual do host e o registra. Uma sessão já aberta hoje não se move. |
| As alterações não aparecem | Encerre completamente e reinicie o cliente DSH: o bundle fica em cache do carregador de módulos. |

## License

MIT
