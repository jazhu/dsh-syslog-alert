# Central de Alertas Inteligente (`dsh-syslog-alert`)

Executa um receptor syslog UDP/TCP **dentro do DSH** e transforma cada alerta do dispositivo
em uma análise completa: parse → pré-filtro → triagem por LLM → coleta SSH somente leitura no
dispositivo → veredito com passos de remediação. Os alertas e suas cronologias aparecem em uma
aba da barra lateral direita.

**Somente leitura por design.** Um payload syslog é entrada não confiável, então o texto do log
nunca pode virar um comando. Qualquer comando proposto pelo modelo precisa passar por uma lista
branca de prefixos `show` / `display` / `get` / `diagnose`; escritas só viram rascunhos para
aprovação humana.

## Requirements

- DSH com os plugins `agents` / `subagents` habilitados (análise profunda e sessões diárias)
- Node 22.19+ ou 24+ (o runtime embutido do DSH atende)
- Para a **coleta de dados do dispositivo**: o plugin `dsh-hillstone-cli-ops` precisa estar
  instalado e habilitado no mesmo DSH. Sem ele, os alertas chegam e são triados, mas a coleta
  SSH é pulada.

## Install

```bash
dsh plugin add /path/to/dsh-syslog-alert-0.1.0.tgz
```

Depois abra as configurações do plugin, defina as portas de escuta (UDP+TCP 1514 por padrão) e
aponte o encaminhador syslog do dispositivo para o endereço do host DSH.

## How it works

```
socket → parse → pre-filter (zero LLM) → fingerprint dedup → per-device rate limit
       → alert record → queue pump → triage → collect → verdict → SSE
```

Tudo acima da fila é síncrono e barato; tudo abaixo pode levar segundos. Quatro travões
independentes protegem contra um flap que emite milhares de linhas: deduplicação por
impressão digital, limite por dispositivo por minuto, comporta global de concorrência e
agregação de tempestade.

## Safety model

- O texto do log é sempre entregue ao modelo como **dados** rotulados, nunca como instruções.
- Um comando proposto precisa casar com a lista branca de prefixos; separadores, travessia de
  caminho e prefixos de escrita conhecidos são rejeitados antes da execução.
- Um quadro cujo remetente não é um dispositivo mapeado é armazenado e sinalizado, mas nunca
  pode disparar um comando SSH.
- Quadros que não podem ser interpretados com confiança são armazenados e exibidos, e nunca
  enviados ao modelo.

## Configuration

Pelo painel de configurações: portas e transportes, mapeamento de origens, lista branca de
prefixos, provider/modelo de LLM, chave de análise profunda e sessão diária.

## Troubleshooting

| Sintoma | Causa e correção |
| --- | --- |
| Nenhum alerta chega | Verifique as **portas vinculadas**; uma falha de bind (ex.: a 514 exige elevação no Linux) é reportada como porta com falha, não ignorada. |
| Alertas chegam, sem veredicto | A chamada ao LLM falhou ou foi limitada. Veja os contadores de dedup/limite/descarte e a cronologia do alerta. |
| A coleta falha | `dsh-hillstone-cli-ops` não está instalado/habilitado, ou o dispositivo não tem credenciais. A coleta é uma etapa separada; o alerta continua válido. |
| "o host não tem subagent provider" | Habilite os plugins `agents`/`subagents` do host e escolha um provider na lista suspensa (a lista é lida do host, não digitada). |
| Alterações não aparecem | Encerre completamente e reinicie o cliente DSH — o bundle fica em cache do carregador de módulos. |

## License

MIT
