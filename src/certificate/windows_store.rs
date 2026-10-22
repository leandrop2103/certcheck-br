//! Integração nativa com a Windows Cryptography API (Crypt32.dll).
//!
//! Permite enumerar o repositório pessoal do Windows (CurrentUser\MY),
//! detectar chaves privadas vinculadas (KSP/CSP) e diferenciar certificados
//! A1 (software) de A3 (hardware/smart card).

use crate::certificate::parser::parse_x509_der;
use crate::certificate::types::CertificateSource;
use crate::certificate::CertificateInfo;
use crate::error::{CertCheckError, Result};
use std::ffi::c_void;

const CERT_KEY_PROV_INFO_PROP_ID: u32 = 2;
const CERT_KEY_SPEC_PROP_ID: u32 = 6;
const CRYPT_EXPORTABLE: u32 = 0x00000001;
const PKCS12_NO_PERSIST_KEY: u32 = 0x00008000;
const PKCS12_ALWAYS_CNG_KSP: u32 = 0x00000200;
const PKCS12_ONLY_CERTIFICATES: u32 = 0x00000400;

#[repr(C)]
struct CryptDataBlob {
    cb_data: u32,
    pb_data: *const u8,
}

#[repr(C)]
struct CertContext {
    dw_cert_encoding_type: u32,
    pb_cert_encoded: *const u8,
    cb_cert_encoded: u32,
    p_cert_info: *const c_void,
    h_cert_store: *const c_void,
}

#[repr(C)]
struct CryptKeyProvInfo {
    pwsz_container_name: *mut u16,
    pwsz_prov_name: *mut u16,
    dw_prov_type: u32,
    dw_flags: u32,
    c_prov_param: u32,
    rg_prov_param: *mut c_void,
    dw_key_spec: u32,
}

#[link(name = "crypt32")]
extern "system" {
    fn CertOpenSystemStoreW(
        h_prov: usize,
        sz_subsystem_protocol: *const u16,
    ) -> *mut c_void;

    fn CertEnumCertificatesInStore(
        h_cert_store: *mut c_void,
        p_prev_cert_context: *const CertContext,
    ) -> *const CertContext;

    fn CertCloseStore(
        h_cert_store: *mut c_void,
        dw_flags: u32,
    ) -> i32;

    fn CertGetCertificateContextProperty(
        p_cert_context: *const CertContext,
        dw_prop_id: u32,
        pv_data: *mut c_void,
        pcb_data: *mut u32,
    ) -> i32;

    fn PFXImportCertStore(
        p_pfx: *const CryptDataBlob,
        sz_password: *const u16,
        dw_flags: u32,
    ) -> *mut c_void;

    fn PFXVerifyPassword(
        p_pfx: *const CryptDataBlob,
        sz_password: *const u16,
        dw_flags: u32,
    ) -> i32;

    #[allow(dead_code)]
    fn PFXIsPFXBlob(
        p_pfx: *const CryptDataBlob,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}


/// Encontra e carrega todos os certificados instalados no repositório pessoal do Windows (`CurrentUser\MY`).
///
/// Prioriza certificados que possuam chave privada associada (A1/A3).
pub fn enumerate_a1_certificates() -> Result<Vec<CertificateInfo>> {
    let mut certificates = Vec::new();

    // Converte "MY\0" para UTF-16
    let store_name_wide: Vec<u16> = "MY\0".encode_utf16().collect();

    unsafe {
        let h_store = CertOpenSystemStoreW(0, store_name_wide.as_ptr());
        if h_store.is_null() {
            return Err(CertCheckError::ProviderError {
                provider: "WindowsStore".to_string(),
                reason: "Falha ao abrir repositório pessoal do Windows (CurrentUser\\MY).".to_string(),
            });
        }

        let mut p_context: *const CertContext = std::ptr::null();

        loop {
            p_context = CertEnumCertificatesInStore(h_store, p_context);
            if p_context.is_null() {
                break;
            }

            let ctx = &*p_context;
            if ctx.pb_cert_encoded.is_null() || ctx.cb_cert_encoded == 0 {
                continue;
            }

            let der_bytes = std::slice::from_raw_parts(ctx.pb_cert_encoded, ctx.cb_cert_encoded as usize);

            // 1. Verifica se o certificado possui chave privada associada (CERT_KEY_PROV_INFO_PROP_ID)
            let (has_private_key, is_hardware) = check_private_key_info(p_context);

            let source = CertificateSource::WindowsStore {
                store_name: "MY (Pessoal)".to_string(),
            };

            match parse_x509_der(der_bytes, source, has_private_key, is_hardware) {
                Ok(cert_info) => {
                    certificates.push(cert_info);
                }
                Err(e) => {
                    tracing::warn!("Ignorando certificado inválido ou não decodificável do Windows Store: {}", e);
                }
            }
        }

        CertCloseStore(h_store, 0);
    }

    // Ordena os certificados priorizando:
    // 1. Possui chave privada (A1 instalados)
    // 2. Não expirados
    // 3. Mais recentes
    let now = chrono::Utc::now();
    certificates.sort_by(|a, b| {
        b.has_private_key
            .cmp(&a.has_private_key)
            .then_with(|| a.is_currently_valid(now).cmp(&b.is_currently_valid(now)).reverse())
            .then_with(|| b.not_after.cmp(&a.not_after))
    });

    tracing::info!(
        "Enumeração do Windows Certificate Store concluída: {} certificado(s) lido(s).",
        certificates.len()
    );

    Ok(certificates)
}

/// Inspeciona as propriedades de chave do Windows CryptoAPI para verificar a presença de chave privada.
unsafe fn check_private_key_info(p_context: *const CertContext) -> (bool, bool) {
    let mut cb_data: u32 = 0;

    // Primeiro teste: CERT_KEY_PROV_INFO_PROP_ID (detalha o container e provider)
    let has_prov_info = CertGetCertificateContextProperty(
        p_context,
        CERT_KEY_PROV_INFO_PROP_ID,
        std::ptr::null_mut(),
        &mut cb_data,
    ) != 0 && cb_data > 0;

    if has_prov_info {
        let mut buffer: Vec<u8> = vec![0u8; cb_data as usize];
        if CertGetCertificateContextProperty(
            p_context,
            CERT_KEY_PROV_INFO_PROP_ID,
            buffer.as_mut_ptr() as *mut c_void,
            &mut cb_data,
        ) != 0 {
            let prov_info = &*(buffer.as_ptr() as *const CryptKeyProvInfo);
            let mut is_hardware = false;

            if !prov_info.pwsz_prov_name.is_null() {
                let prov_name = read_wide_string(prov_info.pwsz_prov_name);
                let prov_lower = prov_name.to_lowercase();
                if prov_lower.contains("smart card")
                    || prov_lower.contains("token")
                    || prov_lower.contains("aladdin")
                    || prov_lower.contains("safenet")
                    || prov_lower.contains("etoken")
                    || prov_lower.contains("gemalto")
                    || prov_lower.contains("oberthur")
                    || prov_lower.contains("giesecke")
                {
                    is_hardware = true;
                }
            }

            return (true, is_hardware);
        }
    }

    // Segundo teste: CERT_KEY_SPEC_PROP_ID
    let mut key_spec: u32 = 0;
    let mut key_spec_size = std::mem::size_of::<u32>() as u32;
    let has_key_spec = CertGetCertificateContextProperty(
        p_context,
        CERT_KEY_SPEC_PROP_ID,
        &mut key_spec as *mut u32 as *mut c_void,
        &mut key_spec_size,
    ) != 0;

    if has_key_spec {
        return (true, false);
    }

    (false, false)
}

/// Lê uma string terminada em nulo a partir de um ponteiro UTF-16.
unsafe fn read_wide_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

/// Verifica se a senha informada abre com sucesso o container PKCS#12 (.pfx / .p12).
pub fn verify_pfx_password(pfx_data: &[u8], password: &str) -> bool {
    let wide_pw: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();
    let blob = CryptDataBlob {
        cb_data: pfx_data.len() as u32,
        pb_data: pfx_data.as_ptr(),
    };
    unsafe { PFXVerifyPassword(&blob, wide_pw.as_ptr(), 0) != 0 }
}

/// Importa e analisa os certificados contidos em um arquivo PKCS#12 (.pfx / .p12).
///
/// Tenta a senha fornecida pelo usuário, heurística pelo nome do arquivo (ex: "Senha12345678")
/// e senhas comuns de testes de certificados brasileiros.
pub fn import_pfx_certificates(
    pfx_data: &[u8],
    password: Option<&str>,
    file_path: &str,
) -> Result<Vec<CertificateInfo>> {
    let blob = CryptDataBlob {
        cb_data: pfx_data.len() as u32,
        pb_data: pfx_data.as_ptr(),
    };

    // Monta lista de senhas candidatas a testar
    let mut candidates: Vec<String> = Vec::new();
    if let Some(pw) = password {
        if !pw.is_empty() {
            candidates.push(pw.to_string());
        }
    }

    // Heurística do nome do arquivo (ex: CD_Armindo_Senha12345678.pfx -> 12345678)
    let file_stem = std::path::Path::new(file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if let Some(pos) = file_stem.to_lowercase().find("senha") {
        let after = &file_stem[pos + 5..];
        let pwd_cand: String = after.chars().take_while(|c| c.is_alphanumeric()).collect();
        if !pwd_cand.is_empty() && !candidates.contains(&pwd_cand) {
            candidates.push(pwd_cand);
        }
    }

    // Senhas padrão e de teste conhecidas do ambiente de desenvolvimento
    for common in &["", "12345678", "afc2026", "aire2026", "sklrn2026", "1234", "123456", "123456789"] {
        let s = common.to_string();
        if !candidates.contains(&s) {
            candidates.push(s);
        }
    }

    // Testa as senhas candidatas
    let mut matching_pw = None;
    for cand in &candidates {
        let wide: Vec<u16> = cand.encode_utf16().chain(std::iter::once(0)).collect();
        let ok = unsafe { PFXVerifyPassword(&blob, wide.as_ptr(), 0) != 0 };
        if ok {
            matching_pw = Some(cand.clone());
            break;
        }
    }

    let Some(valid_pw) = matching_pw else {
        return Err(CertCheckError::InvalidPasswordOrCorruptPkcs12);
    };

    let wide_pw: Vec<u16> = valid_pw.encode_utf16().chain(std::iter::once(0)).collect();

    // Tenta abrir o container PKCS#12 testando combinações de flags
    let flag_combinations = [
        CRYPT_EXPORTABLE | PKCS12_NO_PERSIST_KEY,
        PKCS12_ALWAYS_CNG_KSP | PKCS12_NO_PERSIST_KEY,
        PKCS12_ALWAYS_CNG_KSP,
        PKCS12_NO_PERSIST_KEY,
        CRYPT_EXPORTABLE,
        0,
        PKCS12_ONLY_CERTIFICATES,
    ];

    let mut h_store: *mut c_void = std::ptr::null_mut();
    for &flags in &flag_combinations {
        h_store = unsafe { PFXImportCertStore(&blob, wide_pw.as_ptr(), flags) };
        if !h_store.is_null() {
            break;
        }
    }

    if h_store.is_null() {
        let err_code = unsafe { GetLastError() };
        return Err(CertCheckError::ProviderError {
            provider: "WindowsCryptoAPI".to_string(),
            reason: format!(
                "Falha ao abrir container PKCS#12 (.PFX) via PFXImportCertStore (Código Win32: 0x{:08X}).",
                err_code
            ),
        });
    }

    let mut certificates = Vec::new();
    let mut p_context: *const CertContext = std::ptr::null();

    loop {
        p_context = unsafe { CertEnumCertificatesInStore(h_store, p_context) };
        if p_context.is_null() {
            break;
        }

        let ctx = unsafe { &*p_context };
        if ctx.pb_cert_encoded.is_null() || ctx.cb_cert_encoded == 0 {
            continue;
        }

        let der_bytes = unsafe {
            std::slice::from_raw_parts(ctx.pb_cert_encoded, ctx.cb_cert_encoded as usize)
        };

        let (mut has_pk, is_hw) = unsafe { check_private_key_info(p_context) };
        if !has_pk {
            let mut cb = 0u32;
            let has_prov = unsafe {
                CertGetCertificateContextProperty(
                    p_context,
                    CERT_KEY_PROV_INFO_PROP_ID,
                    std::ptr::null_mut(),
                    &mut cb,
                ) != 0
            };
            if has_prov {
                has_pk = true;
            }
        }

        let source = CertificateSource::FilePfx(file_path.to_string());

        match parse_x509_der(der_bytes, source, has_pk, is_hw) {
            Ok(cert_info) => certificates.push(cert_info),
            Err(e) => tracing::warn!("Aviso ao analisar certificado extraído do PFX: {}", e),
        }
    }

    unsafe {
        CertCloseStore(h_store, 0);
    }

    if certificates.is_empty() {
        return Err(CertCheckError::CertificateParseError(
            "Nenhum certificado X.509 pôde ser extraído do arquivo .PFX.".to_string(),
        ));
    }

    // Ordena priorizando:
    // 1. Possui chave privada associada (o certificado do titular)
    // 2. Não é Autoridade Certificadora (folha/assinante antes de intermediárias e raiz)
    // 3. Válido e com maior período de validade
    let now = chrono::Utc::now();
    certificates.sort_by(|a, b| {
        b.has_private_key
            .cmp(&a.has_private_key)
            .then_with(|| {
                let a_is_ca = a.extensions.basic_constraints.as_ref().map(|bc| bc.is_ca).unwrap_or(false);
                let b_is_ca = b.extensions.basic_constraints.as_ref().map(|bc| bc.is_ca).unwrap_or(false);
                a_is_ca.cmp(&b_is_ca)
            })
            .then_with(|| a.is_currently_valid(now).cmp(&b.is_currently_valid(now)).reverse())
            .then_with(|| b.not_after.cmp(&a.not_after))
    });

    Ok(certificates)
}
