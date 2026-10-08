# Centro de Alertas Inteligente (`dsh-syslog-alert`)

Ejecuta un receptor syslog UDP/TCP **dentro de DSH** e ingiere cada alerta del dispositivo en
tiempo real: parseo → prefiltrado → deduplicación por huella → límite por dispositivo → registro
de alerta → entrega a la sesión de alertas del día. Las alertas fluyen en el panel; haga clic
en una fila para ver la cronología completa de esa alerta.

**El análisis se delega al agente de la sesión.** El propio plugin no hace llamadas a modelos: el
primer log del día abre una sesión ordinaria, los logs siguientes se publican en ella, y el agente
los analiza y llama a la herramienta `syslog_conclude` para escribir la conclusión de vuelta en el
detalle de la alerta.

> English version: [README.md](./README.md)。中文说明见 [README-zh.md](./README-zh.md)。

## Requirements

- DSH con `sessionController` disponible (integrado en el host; la sesión de alertas del día no
  necesita provider ni elección de modelo)
- Node 22.19+ o 24+ (el runtime incluido de DSH cumple)

## Install

```bash
dsh plugin add /path/to/dsh-syslog-alert-0.1.0.tgz
```

Luego abra los ajustes del plugin, defina los puertos de escucha (UDP+TCP 1514 por defecto) y
apunte el reenviador syslog del dispositivo a la dirección del host DSH.

## How it works

```
socket → parse → pre-filter → fingerprint dedup → per-device rate limit
       → alert record → day-session delivery → SSE
```

La ruta de ingesta es completamente síncrona y barata. Cuatro frenos independientes protegen
contra un flap que emite miles de líneas: prefiltrado, deduplicación por huella, límite por
dispositivo y minuto, y agregación de tormentas. El análisis no está en la ruta de ingesta —
ocurre en la sesión de alertas del día, hecho por el agente.

## Safety model

- El texto del log entra siempre al prompt dentro de una valla etiquetada como **datos**, nunca
  mezclado con instrucciones; la sesión del día comparte un mismo neutralizador, así que una valla
  de cierre falsificada se reescribe y queda sin efecto.
- El id de la alerta, el nombre del dispositivo y el log original los añade el propio plugin; un
  prompt personalizado solo puede reemplazar la línea de instrucción, y nada del log puede
  desplazarlos.
- Un paquete cuyo emisor no es un dispositivo mapeado sigue la política de no mapeados: se guarda
  y se marca por defecto.
- Los paquetes que no se pueden parsear con confianza se guardan y se muestran, sin usarse como
  campos estructurados.

## Configuration

Desde el panel de ajustes: puertos y transportes, mapeo de orígenes, y la sesión de alertas del
día (prefijo del título, workspace, prompt).

## Troubleshooting

| Síntoma | Causa y solución |
| --- | --- |
| No llegan alertas | Revise los **puertos vinculados**; un fallo de bind (p. ej. el 514 requiere elevación en Linux) se informa como puerto fallido, no se ignora. |
| El detalle no muestra "当日会话分析结论" | La conclusión la escribe el agente de la sesión llamando a `syslog_conclude`. Tras una entrega correcta el detalle muestra primero "会话分析中"; si se queda ahí, el agente no llamó a la herramienta, o la alerta ya salió del anillo en memoria. |
| La sesión de alertas no se creó | El estado del panel da la razón: el interruptor apagado (当日会话未启用), el host no ofrece `sessionController`, o el primer log del día no ha llegado. `GET /syslog-api/auto-session` muestra el mismo estado. |
| La sesión abrió en un workspace equivocado | Un workspace que no es ruta absoluta se ignora (el `cwd` de DSH solo acepta rutas absolutas); el plugin vuelve al workspace actual del host y lo registra. Una sesión ya abierta hoy no se mueve. |
| Los cambios no se ven | Cierre por completo y reinicie el cliente DSH: el bundle está en caché del cargador de módulos. |

## License

MIT
