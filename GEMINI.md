# Regras de Desenvolvimento e Diretrizes do Projeto (`GEMINI.md`)

Este arquivo define os padrões obrigatórios e automáticos que o assistente de IA (Antigravity) deve seguir **sempre que fizer qualquer alteração ou build neste repositório**.

---

## 📌 1. Regra de Versionamento Obrigatório (SemVer)
- **Toda alteração de código, melhoria ou correção de bug DEVE obrigatoriamente incrementar o número da versão** no arquivo `Cargo.toml`.
- Exemplo: de `0.1.0` para `0.1.1`.
- Nunca gerar uma nova compilação sem incrementar a versão, pois o auto-atualizador (`updater.rs`) depende de versões estritamente crescentes para que os usuários recebam as atualizações automaticamente do GitHub Releases.

---

## 🛠️ 2. Regra de Compilação Universal para Windows (Windows 7 SP1 ao Windows 11)

> [!IMPORTANT]
> O CertCheck BR possui compatibilidade nativa com Windows 7 SP1, 8, 8.1, 10 e 11 x86_64.
> O módulo `src/win7_compat.rs` provê shims e fallbacks automáticos para:
> - `GetSystemTimePreciseAsFileTime` (kernel32.dll -> fallback para `GetSystemTimeAsFileTime`)
> - `ProcessPrng` (bcryptprimitives.dll -> fallback para `RtlGenRandom` / `SystemFunction036` em advapi32.dll)
> - `WaitOnAddress`, `WakeByAddressAll`, `WakeByAddressSingle` (api-ms-win-core-synch-l1-2-0.dll -> fallback com `SRWLock` e `ConditionVariable`)
>
> A compilação estática (`target-feature=+crt-static`) está configurada no `.cargo/config.toml` para eliminar a dependência externa de `libunwind.dll`.

### Comando de Build de Produção:
```powershell
cargo build --release
```

### Validação de Símbolos Obrigatória:
Após compilar, confirme que nenhuma dependência indevida está presente na tabela de importações do executável:
```powershell
& (Get-Item "C:\Users\Leandro\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-*\bin\llvm-readobj.exe").FullName --coff-imports certcheck-br.exe | Select-String "libunwind|bcryptprimitives|GetSystemTimePreciseAsFileTime"
```
*(O comando acima deve retornar vazio, confirmando ausência dessas dependências).*

---

## 📂 3. Cópia e Sincronização dos Binários
- O script `linker_wrapper.py` já copia automaticamente o binário compilado para a raiz: `d:\rust\certicheck\certcheck-br.exe`.
- Para distribuição, garanta que a pasta `dist/` também receba a cópia atualizada:
```powershell
if (!(Test-Path "dist")) { New-Item -ItemType Directory -Path "dist" }
Copy-Item -Force certcheck-br.exe dist\certcheck-br.exe
```

---

## 🚀 4. Regra de Publicação no GitHub (Código + Release para Auto-Updater)

Sempre que concluir um ciclo de melhorias e incrementar a versão:

### Passo A: Repositório de Código-Fonte (`leandrop2103/certcheck-br`)
```powershell
git add .
git commit -m "feat/fix: <descrição sucinta das alterações> (v<VERSÃO>)"
git push origin master
git tag -a v<VERSÃO> -m "Release v<VERSÃO>"
git push origin v<VERSÃO>
```

### Passo B: Publicação da Release no GitHub (Disponibilização do Executável para Auto-Update)
O executável atualizado (`certcheck-br.exe`) deve ser anexado como asset da release para que o módulo `updater.rs` detecte e baixe automaticamente para os clientes:
```powershell
gh release create v<VERSÃO> certcheck-br.exe --repo leandrop2103/certcheck-br --title "CertCheck BR v<VERSÃO>" --notes "<Notas da versão resumidas>"
```

---

## 🔒 5. Segurança ICP-Brasil e Boas Práticas
1. **Chaves Privadas Invioláveis**: O CertCheck BR **NUNCA** exporta, armazena, transmite ou extrai chaves privadas.
2. **Nenhum Certificado no Git**: Arquivos `.pfx`, `.p12`, `.cer`, `.key` estão bloqueados no `.gitignore`. Nunca faça commit de certificados reais.
3. **Logs Sanitizados**: O `MemoryLogBuffer` sanitiza automaticamente ocorrências acidentais de senhas ou chaves.
4. **Local-First**: Operações de diagnóstico e validação funcionam offline. Apenas verificações de CRL/OCSP e o auto-updater requerem conexão com a internet.
