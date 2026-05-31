# binforge
A Python tool for analyzing and highlighting magic bytes in binary files.

# 🔬 BinForge v2.0.0
### Binary Magic Byte Forensics Engine

BinForge é uma ferramenta de análise forense binária profissional que detecta **magic bytes** em arquivos binários, mapeia todos os blocos de dados embutidos e gera relatórios detalhados em múltiplos formatos.

---

## ✨ Features

| Recurso | Descrição |
|---------|-----------|
| 🧠 **120+ assinaturas** | JSON database com imagem, vídeo, áudio, executáveis, arquivos, cripto, 3D e mais |
| 🔍 **Scan profundo** | Localiza streams embutidos em qualquer posição do arquivo |
| 🃏 **Wildcards** | Suporte a padrões com bytes variáveis (`??`) |
| 📦 **Blocos mapeados** | Separa cada formato identificado com start/end offset exatos |
| 🔑 **SHA-256** | Hash de cada bloco individual |
| 📤 **Extração** | Exporta cada bloco como arquivo separado com extensão correta |
| 📊 **5 formatos de saída** | Terminal colorido, JSON, CSV, Markdown, HTML |
| ⚡ **mmap** | Leitura via memory-map para arquivos grandes |
| 🏷️ **Filtros** | Filtre por categoria, tamanho mínimo, banco de dados personalizado |

---

## 🚀 Instalação

Requer apenas **Python 3.8+**, sem dependências externas.

```bash
git clone <repo>
cd binforge
python binforge.py --help
```

---

## 📖 Uso

### Scan básico
```bash
python binforge.py firmware.bin
```

### Verboso (mostra hex/ASCII preview)
```bash
python binforge.py firmware.bin -v
```

### Filtrar só imagens e áudio
```bash
python binforge.py arquivo.bin --categories image,audio
```

### Ignorar blocos menores que 512 bytes
```bash
python binforge.py arquivo.bin --min-size 512
```

### Exportar todos os formatos
```bash
python binforge.py arquivo.bin --all-formats -o resultados/
```

### Exportar formatos específicos
```bash
python binforge.py arquivo.bin --json relatorio.json --html relatorio.html
```

### Extrair cada bloco como arquivo
```bash
python binforge.py arquivo.bin --extract -o saida/
```

### Modo silencioso (JSON puro no stdout — ideal para pipelines)
```bash
python binforge.py arquivo.bin --quiet | jq '.blocks[].signature_name'
```

### Listar categorias disponíveis
```bash
python binforge.py --list-categories
```

### Listar assinaturas de uma categoria
```bash
python binforge.py --list-signatures executable
```

---

## 📁 Estrutura do Projeto

```
binforge/
├── binforge.py            ← CLI principal (entry point)
├── core/
│   ├── scanner.py         ← Motor de scan (mmap + pattern matching)
│   └── reporter.py        ← Geração de relatórios (terminal/JSON/CSV/MD/HTML)
├── data/
│   └── magic_bytes.json   ← Base de assinaturas (editável/extensível)
├── test_samples/          ← Amostras de teste
└── README.md
```

---

## 🗂️ Banco de Dados de Assinaturas

O arquivo `data/magic_bytes.json` é totalmente editável. Estrutura de cada entrada:

```json
{
  "name": "PNG",
  "category": "image",
  "mime": "image/png",
  "extensions": [".png"],
  "magic": "89504E470D0A1A0A",
  "offset": 0,
  "description": "PNG image file"
}
```

### Campos

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `name` | string | Identificador único da assinatura |
| `category` | string | Categoria (image, audio, archive, executable…) |
| `mime` | string | MIME type oficial |
| `extensions` | list | Extensões comuns |
| `magic` | string | Bytes em hexadecimal. Use `??` para wildcards |
| `offset` | int | Posição no arquivo. `-N` = relativo ao EOF |
| `wildcard` | string | Token wildcard customizado (padrão: `??`) |
| `is_trailer` | bool | `true` para marcadores de fim de arquivo |
| `description` | string | Descrição legível |

### Adicionando sua própria assinatura

```json
{
  "name": "MINHA_ASSINATURA",
  "category": "custom",
  "mime": "application/x-custom",
  "extensions": [".meu"],
  "magic": "DEADBEEF??FF",
  "offset": 0,
  "description": "Meu formato proprietário"
}
```

---

## 📊 Categorias disponíveis

| Categoria | Exemplos |
|-----------|----------|
| `image` | JPEG, PNG, GIF, WebP, HEIC, AVIF, JXL, BMP, TIFF |
| `video` | MP4, MKV, AVI, MOV, FLV, WebM, MPEG |
| `audio` | MP3, FLAC, OGG, WAV, MIDI, AAC |
| `archive` | ZIP, RAR, 7Z, GZip, BZip2, XZ, TAR, Zstd, LZ4 |
| `executable` | ELF, PE/MZ, Mach-O, WASM, DEX, Java .class, Lua |
| `document` | PDF, DOCX, DOC, RTF |
| `database` | SQLite, MSSQL, MySQL |
| `crypto` | PEM, DER, PKCS12, GPG, AES |
| `network` | PCAP, PCAPNG |
| `font` | TTF, OTF, WOFF, WOFF2 |
| `3d` | Blender, FBX, glTF/GLB, STL |
| `medical` | DICOM, NIfTI |
| `disk` | ISO, VMDK, VHD, QCOW |
| `shader` | DXBC, SPIR-V |
| `data` | Protobuf, Avro, Parquet, ORC, HDF5, CBOR |
| `mobile` | APK, IPA, bplist |
| `windows` | LNK, REG, EVTX, Prefetch, Minidump |

---

## 🔧 Opções completas

```
usage: binforge FILE [options]

positional:
  FILE                   Arquivo binário para analisar

database:
  --db PATH              Banco de assinaturas JSON (padrão: data/magic_bytes.json)

filtragem:
  --categories C1,C2     Categorias para escanear (ex: image,audio)
  --min-size BYTES        Ignorar blocos menores que N bytes

saída:
  --output DIR           Diretório de saída (padrão: binforge_output/)
  --json FILE            Escrever relatório JSON
  --csv FILE             Escrever relatório CSV
  --markdown FILE        Escrever relatório Markdown
  --html FILE            Escrever relatório HTML
  --all-formats          Gerar todos os formatos no diretório --output

extração:
  --extract              Extrair cada bloco como arquivo separado

display:
  --verbose              Mostrar preview hex/ASCII de cada bloco
  --no-color             Desativar cores ANSI
  --quiet                Suprimir banner; emitir apenas JSON no stdout
  --log-level LEVEL      Nível de log interno (DEBUG|INFO|WARNING|ERROR)

info:
  --list-categories      Listar categorias disponíveis e sair
  --list-signatures CAT  Listar assinaturas de uma categoria e sair
  --version              Mostrar versão e sair
```

---

## 📄 Exemplo de saída JSON

```json
{
  "generated": "2025-01-15T10:30:00Z",
  "total_blocks": 3,
  "blocks": [
    {
      "index": 0,
      "start_offset": 0,
      "end_offset": 100,
      "size": 100,
      "signature_name": "JPEG",
      "signature_category": "image",
      "mime": "image/jpeg",
      "extensions": [".jpg", ".jpeg"],
      "description": "JPEG image file",
      "sha256": "a9b7f636...",
      "hex_preview": "FFD8FFE0...",
      "ascii_preview": "........"
    }
  ]
}
```

---

## 🤝 Extensibilidade

BinForge foi projetado para ser uma **biblioteca** além de uma CLI:

```python
from core.scanner import SignatureDatabase, BinaryScanner
from pathlib import Path

db      = SignatureDatabase(Path("data/magic_bytes.json"))
scanner = BinaryScanner(db, min_block_size=16)
blocks  = scanner.scan_file(Path("arquivo.bin"))

for blk in blocks:
    print(f"[{blk.index}] {blk.match.signature.name} @ 0x{blk.start_offset:X} ({blk.size} bytes)")

# Ou escanear bytes diretamente:
blocks = scanner.scan_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
```

---

*BinForge v2.0.0 — Feito para análise forense, CTFs, engenharia reversa e pesquisa de segurança.*
