# Política de Segurança — CertCheck BR

O **CertCheck BR** foi projetado seguindo as mais rigorosas diretrizes de segurança criptográfica e privacidade estabelecidas pelo padrão X.509 (RFC 5280) e pelas normas da Infraestrutura de Chaves Públicas Brasileira (ICP-Brasil / DOC-ICP-04).

---

## 🔒 Princípios de Segurança e Não-Violação

1. **Inviolabilidade de Chaves Privadas:**
   - O CertCheck BR **NUNCA** exporta, armazena, transmite ou extrai chaves privadas para fora do sistema operacional ou do hardware criptográfico (Tokens/Smart Cards A3).
   - As operações criptográficas de assinatura são executadas delegando a operação diretamente à Windows Cryptography API (Crypt32 / CNG) e aos drivers certificados dos fabricantes.

2. **Operação Local-First (Offline):**
   - Todas as rotinas de análise estrutural ASN.1, decodificação de extensões, cálculo de fingerprints (SHA-256/SHA-1) e verificação de regras de identidade ocorrem localmente na máquina do usuário.
   - Apenas verificações de revogação externa (CRL e OCSP) requisitam acesso de rede aos pontos de distribuição oficiais das Autoridades Certificadoras emissoras.

3. **Sem Coleta de Dados Pessoais ou Telemetria:**
   - A aplicação não contém telemetria oculta, rastreadores ou envio de metadados para servidores de terceiros.
   - Senhas de arquivos PKCS#12 e PINs de tokens nunca são gravados em logs ou em disco.

---

## 🛡️ Reportando Vulnerabilidades

Caso identifique qualquer inconsistência de segurança ou comportamento anômalo:
1. Abra uma *Security Advisory* privada ou envie um e-mail para o mantenedor responsável através do perfil do GitHub (`leandrop2103`).
2. Descreva os passos para reprodução e o impacto técnico observado.
3. Não divulgue publicamente a vulnerabilidade antes de uma análise prévia e correção coordenada.
