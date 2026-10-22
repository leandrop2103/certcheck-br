# Regras do Projeto (AGENTS.md)

Este repositório segue estritamente as diretrizes definidas em [GEMINI.md](file:///d:/rust/certicheck/GEMINI.md):

1. **Versionamento Obrigatório (SemVer):** Toda alteração de código ou correção de bug exige incremento de versão no `Cargo.toml`.
2. **Build Universal Windows:** Compilação com `cargo build --release` (utilizando `.cargo/config.toml` com `+crt-static` e módulo `src/win7_compat.rs`).
3. **Cópia de Binários:** O binário é sincronizado na raiz `certcheck-br.exe` e em `dist/certcheck-br.exe`.
4. **Publicação no GitHub & Auto-Updater:**
   - Commit + Push + Tag `v<VERSÃO>` no repositório `leandrop2103/certcheck-br` (com fallback de consulta para `lpl2103/certcheck-br`).
   - Criação da Release no GitHub com o asset `certcheck-br.exe` via `gh release create` para alimentar o auto-atualizador.
5. **Segurança:** Nunca comitar certificados `.pfx`/`.p12` ou senhas no Git.
