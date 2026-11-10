# ioc-extractor

[![CI](https://github.com/carlpit/ioc-extractor/actions/workflows/ci.yml/badge.svg)](https://github.com/carlpit/ioc-extractor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

Extrai **Indicadores de Comprometimento (IOCs)** de relatórios de inteligência de ameaças, e-mails e logs — com refang, filtro de falsos positivos, allowlists e saída pensada para o analista.

Python puro, só com a biblioteca padrão. Sem dependências, sem chamadas de rede.

## Por que

Relatórios de ameaça publicam indicadores *defanged* (`hxxps://evil[.]com`) misturados com texto, nomes de arquivo e números de versão. Copiar isso à mão para um SIEM, uma blocklist ou um evento no MISP é lento e sujeito a erro. O `ioc-extractor` transforma um relatório numa lista limpa e sem duplicatas, num único comando.

## Funcionalidades

| Tipo | Exemplo | Observações |
|---|---|---|
| `url` | `https://cdn.example.net/view?id=1` | pontuação final e `)` soltos são removidos |
| `domain` | `update-check.badsite.org` | nomes de arquivo como `loader.dll`, `config.json` são filtrados |
| `ipv4` / `ipv6` | `203.0.113.45`, `2001:db8::1` | validados com `ipaddress`; strings de versão como `1.2.3.4.5` são ignoradas |
| `email` | `billing@invoice-update.example` | o domínio não é repetido como `domain` |
| `md5` / `sha1` / `sha256` | `44d886…` | normalizados para minúsculas |
| `cve` | `CVE-2024-3400` | normalizado para maiúsculas |
| `mitre_attack` | `T1059.001` | IDs de técnica e subtécnica do ATT&CK |

- **Refang** da entrada: `hxxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `[@]`, `(at)`, `[://]`, `fxp`
- **Defang** da saída para compartilhar com segurança (relatórios em Markdown saem defanged por padrão)
- `--exclude-private`: descarta IPs privados, de loopback, link-local e faixas de documentação
- `--allowlist`: ignora valores conhecidos como legítimos; um domínio-pai cobre subdomínios, URLs e e-mails
- Saída em **JSON**, **CSV** ou **Markdown**; lê arquivos ou `stdin`

## Instalação

```bash
git clone https://github.com/carlpit/ioc-extractor.git
cd ioc-extractor
pip install -e ".[dev]"
```

## Uso

```bash
# JSON to stdout
ioc-extractor examples/sample_report.txt

# CSV, defanged, only network indicators
ioc-extractor report.txt -f csv --defang -t url,domain,ipv4

# Markdown report for a ticket, ignoring known-good domains
ioc-extractor report.txt -f md --allowlist examples/allowlist.txt -o iocs.md

# Pipe from anything
curl -s https://example.org/advisory.txt | ioc-extractor -f csv
```

Exemplo (trecho) de [`examples/sample_report.txt`](examples/sample_report.txt):

```json
{
  "total": 18,
  "iocs": {
    "url": ["https://cdn-docs.example-cdn.net/view?id=8841", "..."],
    "domain": ["cdn-docs.example-cdn.net", "docs.microsoft.com", "update-check.badsite.org", "..."],
    "ipv4": ["10.20.30.40", "198.51.100.77", "203.0.113.45"],
    "cve": ["CVE-2023-4966", "CVE-2024-3400"],
    "mitre_attack": ["T1053.005", "T1059.001"]
  }
}
```

### Como biblioteca

```python
from ioc_extractor import extract, defang

result = extract(open("report.txt").read(), exclude_private=True, allowlist=["microsoft.com"])
for ioc_type, value in result.rows():
    print(ioc_type, defang(value, ioc_type))
```

## Notas de projeto

- **Precisão acima de recall.** Uma blocklist com falsos positivos quebra a produção (bloquear `config.json` como domínio é um clássico). Candidatos a domínio cujo TLD é uma extensão de arquivo comum são descartados; IPs precisam ser endereços válidos; domínios de e-mail não são contados duas vezes.
- **A ordem da extração** não altera o resultado, porque cada tipo é buscado de forma independente e guardado em conjuntos: a saída é determinística e ordenada.
- O relatório de exemplo é **ficcional** e usa faixas de IP de documentação (RFC 5737 / RFC 3849).

## Testes

```bash
pytest            # unit, CLI and doctests
ruff check .
```

## Roadmap

- [ ] Exportação em bundle STIX 2.1
- [ ] Exportação de evento MISP em JSON
- [ ] Entrada PDF / HTML
- [ ] Enriquecimento opcional (VirusTotal, AbuseIPDB) atrás de chaves de API

## Licença

MIT

---

**Desenvolvido por [carlpit](https://github.com/carlpit)** · Developed by carlpit
