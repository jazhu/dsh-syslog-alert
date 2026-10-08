# स्मार्ट अलर्ट सेंटर (`dsh-syslog-alert`)

DSH के अंदर ही एक UDP/TCP syslog रिसीवर चलाता है और हर डिवाइस अलर्ट को वास्तविक समय में ग्रहण
करता है: parse → pre-filter → fingerprint dedup → प्रति-डिवाइस rate limit → अलर्ट रिकॉर्ड → आज के
अलर्ट सेशन में डिलीवरी। अलर्ट पैनल में दिखते हैं; पूरी टाइमलाइन के लिए किसी पंक्ति पर क्लिक करें।

**विश्लेषण सत्र के agent को सौंपा जाता है।** प्लगइन स्वयं कोई model कॉल नहीं करता: दिन का पहला log
एक साधारण सेशन खोलता है, बाद के log उसी में भेजे जाते हैं, और agent उनका विश्लेषण करके
`syslog_conclude` tool से निष्कर्ष अलर्ट डिटेल पर वापस लिखता है।

> English version: [README.md](./README.md)。中文说明见 [README-zh.md](./README-zh.md)。

## Requirements

- DSH में `sessionController` उपलब्ध (host में बना हुआ; आज के अलर्ट सेशन के लिए न provider न model चुनाव चाहिए)
- Node 22.19+ या 24+ (DSH का अंतर्निहित runtime इस योग्य है)

## Install

```bash
dsh plugin add /path/to/dsh-syslog-alert-0.1.0.tgz
```

फिर प्लगइन की सेटिंग खोलकर listening ports (डिफ़ॉल्ट UDP+TCP 1514) तय करें, और डिवाइस के syslog
forwarder को DSH होस्ट के पते की ओर मोड़ें।

## How it works

```
socket → parse → pre-filter → fingerprint dedup → per-device rate limit
       → alert record → day-session delivery → SSE
```

ग्रहण पथ पूरी तरह synchronous और सस्ता है। हज़ारों लाइनों वाले link flap से चार स्वतंत्र ब्रेक
बचाते हैं: pre-filter, fingerprint dedup, प्रति-डिवाइस प्रति-मिनट rate limit, और storm
aggregation। विश्लेषण ग्रहण पथ पर नहीं है — वह आज के अलर्ट सेशन में agent द्वारा होता है।

## Safety model

- log का पाठ हमेशा fence में बंद **डेटा** के रूप में prompt में जाता है, निर्देशों से कभी नहीं मिलाया जाता;
  दिन का सेशन एक ही defanger साझा करता है, इसलिए नकली closing fence निष्क्रिय कर दिया जाता है।
- अलर्ट id, डिवाइस नाम, और raw log प्लगइन स्वयं जोड़ता है; सेटिंग का custom prompt केवल instruction
  line बदल सकता है, और log का कोई पाठ उन्हें हटा नहीं सकता।
- जिस फ्रेम का sender मैप किया हुआ डिवाइस नहीं है, उसे unmapped policy के अनुसार संग्रहीत और चिह्नित किया जाता है।
- जिन फ्रेमों को भरोसेमंद तरह parse नहीं किया जा सकता, वे संग्रहीत और दिखाए जाते हैं, structured fields के रूप में उपयोग नहीं होते।

## Configuration

इन-ऐप सेटिंग पैनल से: ports और transports, device source mapping, और आज का अलर्ट सेशन
(title prefix, workspace, prompt)।

## Troubleshooting

| लक्षण | कारण और सुधार |
| --- | --- |
| कोई अलर्ट नहीं आता | पैनल के **bound ports** देखें; bind विफलता (जैसे Linux पर 514 को elevation चाहिए) failed port के रूप में दिखती है, चुपचाप नहीं होती। |
| डिटेल में "当日会话分析结论" नहीं | निष्कर्ष सेशन agent द्वारा `syslog_conclude` tool से वापस लिखा जाता है। डिलीवरी के बाद डिटेल पहले "会话分析中" दिखाती है; वहीं रुका रहना agent ने tool नहीं बुलाया, या अलर्ट रिंग से बाहर हो गया। |
| अलर्ट सेशन नहीं बना | पैनल की status में कारण है: switch बंद (当日会话未启用), host `sessionController` सेवा नहीं देता, या दिन का पहला log अभी नहीं आया। `GET /syslog-api/auto-session` वही state दिखाता है। |
| सेशन का workspace गलत जगह है | absolute path न होने पर workspace नज़रअंदाज़ होता है (DSH का `cwd` केवल absolute paths लेता है); प्लगइन host के current workspace पर लौटता है और log करता है। आज पहले से खुला सेशन नहीं हटता। |
| बदलाव दिखाई नहीं दें | DSH क्लाइंट पूरी तरह बंद करके फिर शुरू करें — bundle module loader द्वारा cache किया जाता है। |

## License

MIT
