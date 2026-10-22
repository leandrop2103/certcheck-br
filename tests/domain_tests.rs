//! Testes unitários do domínio do CertCheck BR.

use certcheck_br::certificate::*;
use certcheck_br::error::{CertCheckError, ErrorCategory};
use certcheck_br::icp_brasil::*;
use certcheck_br::logging::{sanitize_log_message, LogEntry, LogLevel, MemoryLogBuffer};
use certcheck_br::report::DiagnosticReport;
use certcheck_br::revocation::*;
use certcheck_br::validation::*;
use chrono::{Duration, Utc};

#[test]
fn test_distinguished_name_display() {
    let dn_cn = DistinguishedName {
        raw: "CN=JOAO DA SILVA, C=BR".to_string(),
        common_name: Some("JOAO DA SILVA".to_string()),
        ..Default::default()
    };
    assert_eq!(dn_cn.display_name(), "JOAO DA SILVA");

    let dn_raw = DistinguishedName {
        raw: "O=EMPRESA SEM CN, C=BR".to_string(),
        common_name: None,
        ..Default::default()
    };
    assert_eq!(dn_raw.display_name(), "O=EMPRESA SEM CN, C=BR");
}

#[test]
fn test_certificate_validity_calculations() {
    let now = Utc::now();
    let cert = CertificateInfo {
        id: "test_cert".to_string(),
        source: CertificateSource::FilePem("test.pem".to_string()),
        cert_type: CertificateType::A1,
        subject: DistinguishedName::default(),
        issuer: DistinguishedName::default(),
        serial_number_hex: "01:02:03".to_string(),
        not_before: now - Duration::days(10),
        not_after: now + Duration::days(50),
        signature_algorithm: "sha256WithRSAEncryption".to_string(),
        public_key: KeyAlgorithm::Rsa { bits: 2048, exponent: 65537 },
        fingerprints: Fingerprints::default(),
        extensions: CertificateExtensions::default(),
        identity: IcpBrasilIdentity::default(),
        has_private_key: true,
        is_hardware_backed: false,
        raw_der: Vec::new(),
    };

    assert!(cert.is_currently_valid(now));
    assert_eq!(cert.days_remaining(now), 50);

    let summary = cert.validity_summary(now);
    assert!(summary.contains("Válido"));
    assert!(summary.contains("50 dias"));
}

#[test]
fn test_icp_brasil_cpf_cnpj_formatting() {
    let id_pf = IcpBrasilIdentity {
        person_type: Some(PersonType::PessoaFisica),
        cpf: Some("12345678901".to_string()),
        ..Default::default()
    };
    assert_eq!(id_pf.formatted_cpf().as_deref(), Some("123.456.789-01"));

    let id_pj = IcpBrasilIdentity {
        person_type: Some(PersonType::PessoaJuridica),
        cnpj: Some("12345678000199".to_string()),
        ..Default::default()
    };
    assert_eq!(id_pj.formatted_cnpj().as_deref(), Some("12.345.678/0001-99"));
}

#[test]
fn test_validation_result_decision_logic() {
    let mut val = ValidationResult::new();

    // Vazio -> Não verificado
    assert_eq!(val.compute_overall_status(), OverallStatus::NaoVerificado);

    // Adiciona apenas checagens PASS -> Apto
    val.add_check(ValidationCheck::new(
        CheckCategory::X509Structure,
        "X.509",
        CheckStatus::Pass,
        "Válido",
        None,
    ));
    assert_eq!(val.compute_overall_status(), OverallStatus::AptoParaUso);
    assert_eq!(val.count_passed(), 1);
    assert_eq!(val.count_warnings(), 0);
    assert_eq!(val.count_errors(), 0);

    // Adiciona WARNING -> Com Restrições
    val.add_check(ValidationCheck::new(
        CheckCategory::RevocationCrl,
        "CRL",
        CheckStatus::Warning,
        "CRL offline",
        None,
    ));
    assert_eq!(val.compute_overall_status(), OverallStatus::ComRestricoes);
    assert_eq!(val.count_warnings(), 1);

    // Adiciona ERROR -> Inapto
    val.add_check(ValidationCheck::new(
        CheckCategory::ValidityPeriod,
        "Validade",
        CheckStatus::Error,
        "Expirado",
        None,
    ));
    assert_eq!(val.compute_overall_status(), OverallStatus::Inapto);
    assert_eq!(val.count_errors(), 1);
}

#[test]
fn test_revocation_summary_logic() {
    let mut summary = RevocationSummary::default();
    assert_eq!(summary.determine_status(), RevocationStatus::NotChecked);

    // Adiciona OCSP indisponível
    summary.ocsp_checks.push(OcspDetails {
        url: "http://ocsp.test".to_string(),
        status: RevocationStatus::Unavailable,
        responder_id: None,
        produced_at: None,
        this_update: None,
        next_update: None,
        revocation_time: None,
        revocation_reason: None,
        error_message: Some("Timeout de conexão".to_string()),
    });
    assert_eq!(summary.determine_status(), RevocationStatus::Unavailable);

    // Adiciona CRL Good
    summary.crl_checks.push(CrlDetails {
        url: "http://crl.test".to_string(),
        status: RevocationStatus::Good,
        this_update: None,
        next_update: None,
        crl_number: None,
        issuer: None,
        revocation_time: None,
        revocation_reason: None,
        error_message: None,
        cached: false,
    });
    assert_eq!(summary.determine_status(), RevocationStatus::Good);

    // Se houver qualquer indicação de REVOKED, o veredito final deve ser REVOKED
    summary.ocsp_checks[0].status = RevocationStatus::Revoked;
    assert_eq!(summary.determine_status(), RevocationStatus::Revoked);
}

#[test]
fn test_icp_brasil_oids_recognition() {
    assert!(is_icp_brasil_oid(OID_ICP_BR_PF_DADOS));
    assert!(is_icp_brasil_oid(OID_ICP_BR_PJ_CNPJ));
    assert!(is_icp_brasil_oid(OID_POLICY_A3));
    assert!(!is_icp_brasil_oid("1.3.6.1.5.5.7.3.2")); // clientAuth

    assert!(describe_icp_oid(OID_ICP_BR_PF_DADOS).is_some());
    assert!(describe_icp_oid(OID_ICP_BR_PJ_CNPJ).is_some());
    assert!(describe_icp_oid(OID_POLICY_A1).is_some());
    assert!(describe_icp_oid("1.2.3.4.5").is_none());
}

#[test]
fn test_error_category_mapping() {
    let err_exp = CertCheckError::CertificateExpired {
        expiration: "2025-01-01".to_string(),
    };
    assert_eq!(err_exp.category(), ErrorCategory::Certificate);

    let err_crl = CertCheckError::CrlError {
        url: "http://crl.exemplo.br".to_string(),
        reason: "404 Not Found".to_string(),
    };
    assert_eq!(err_crl.category(), ErrorCategory::Revocation);

    let err_sign = CertCheckError::SigningError("Chave inacessível".to_string());
    assert_eq!(err_sign.category(), ErrorCategory::Crypto);

    let err_sc = CertCheckError::SmartCardError("Cartão não detectado".to_string());
    assert_eq!(err_sc.category(), ErrorCategory::SmartCard);
}

#[test]
fn test_logging_buffer_and_sanitization() {
    let buffer = MemoryLogBuffer::new(3);

    assert_eq!(sanitize_log_message("teste com senha=1234"), "teste com senha=[REDACTED]");
    assert_eq!(sanitize_log_message("token com pin=5678"), "token com pin=[REDACTED]");

    buffer.push(LogEntry::new(LogLevel::Info, "test", "Mensagem normal"));
    buffer.push(LogEntry::new(LogLevel::Warn, "test", "Tentativa com senha=supersecret123"));
    buffer.push(LogEntry::new(LogLevel::Error, "crypto", "Falha de pin=9876 no token"));

    let entries = buffer.get_filtered(LogLevel::Trace, "");
    assert_eq!(entries.len(), 3);

    // Verifica sanitização
    let warn_entry = entries.iter().find(|e| e.level == LogLevel::Warn).unwrap();
    assert!(!warn_entry.message.contains("supersecret123"));
    assert!(warn_entry.message.contains("[REDACTED]"));

    let error_entry = entries.iter().find(|e| e.level == LogLevel::Error).unwrap();
    assert!(!error_entry.message.contains("9876"));
    assert!(error_entry.message.contains("[REDACTED]"));

    // Teste de capacidade máxima
    buffer.push(LogEntry::new(LogLevel::Info, "test", "Quarta mensagem"));
    let entries_after = buffer.get_filtered(LogLevel::Trace, "");
    assert_eq!(entries_after.len(), 3);
    assert_eq!(entries_after[0].message, "Tentativa com senha=[REDACTED]");
}

#[test]
fn test_report_json_serialization() {
    let now = Utc::now();
    let cert = CertificateInfo {
        id: "cert_json_test".to_string(),
        source: CertificateSource::FilePfx("teste.pfx".to_string()),
        cert_type: CertificateType::A1,
        subject: DistinguishedName {
            raw: "CN=EMPRESA TESTE, C=BR".to_string(),
            common_name: Some("EMPRESA TESTE".to_string()),
            organization: Some("EMPRESA TESTE".to_string()),
            ..Default::default()
        },
        issuer: DistinguishedName {
            raw: "CN=AC RAIZ, C=BR".to_string(),
            common_name: Some("AC RAIZ".to_string()),
            ..Default::default()
        },
        serial_number_hex: "01:AA:BB".to_string(),
        not_before: now - Duration::days(1),
        not_after: now + Duration::days(364),
        signature_algorithm: "sha256WithRSAEncryption".to_string(),
        public_key: KeyAlgorithm::Rsa { bits: 2048, exponent: 65537 },
        fingerprints: Fingerprints {
            sha256: "AA:BB:CC".to_string(),
            sha1: "11:22:33".to_string(),
        },
        extensions: CertificateExtensions::default(),
        identity: IcpBrasilIdentity {
            person_type: Some(PersonType::PessoaJuridica),
            cnpj: Some("12345678000199".to_string()),
            ..Default::default()
        },
        has_private_key: true,
        is_hardware_backed: false,
        raw_der: Vec::new(),
    };

    let mut val = ValidationResult::new();
    val.add_check(ValidationCheck::new(
        CheckCategory::X509Structure,
        "X.509",
        CheckStatus::Pass,
        "Conforme",
        None,
    ));
    val.compute_overall_status();

    let report = DiagnosticReport::new(cert, val, RevocationSummary::default(), None);
    let json = report.to_json_pretty().expect("Falha na serialização JSON");

    assert!(json.contains("EMPRESA TESTE"));
    assert!(json.contains("12345678000199"));
    assert!(json.contains("AptoParaUso"));
    assert!(!json.contains("senha"));
    assert!(!json.contains("private_key_raw"));
}

#[test]
fn test_windows_store_enumeration_runs_without_panic() {
    let result = certcheck_br::certificate::windows_store::enumerate_a1_certificates();
    assert!(result.is_ok(), "Enumeração do Windows Certificate Store deve rodar com sucesso: {:?}", result.err());
    let certs = result.unwrap();
    println!("Certificados encontrados no repositório pessoal: {}", certs.len());
    for c in &certs {
        assert!(!c.id.is_empty());
        assert!(!c.fingerprints.sha1.is_empty());
        assert!(!c.fingerprints.sha256.is_empty());
    }
}

#[test]
fn test_real_pfx_import_and_identity_extraction() {
    use certcheck_br::certificate::windows_store::import_pfx_certificates;

    let local_certs = certcheck_br::gui::certificates::find_local_certificates();
    for path in local_certs {
        let file_name = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(certs) = import_pfx_certificates(&bytes, None, file_name) {
                if !certs.is_empty() {
                    let cert = &certs[0];
                    let clean_title = cert.subject.clean_name();
                    assert!(!clean_title.contains(':'), "clean_name não deve conter o sufixo com dois pontos");
                    println!("Certificado local verificado com sucesso: {}", clean_title);
                }
            }
        }
    }
}

#[test]
fn test_pfx_import_without_password() {
    use certcheck_br::certificate::windows_store::import_pfx_certificates;

    let local_certs = certcheck_br::gui::certificates::find_local_certificates();
    for path in local_certs {
        let file_name = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        if let Ok(bytes) = std::fs::read(&path) {
            let res = import_pfx_certificates(&bytes, None, file_name);
            println!("File: {} -> Result: {:?}", file_name, res.is_ok());
            if let Ok(ref certs) = res {
                println!("  Total certs in PFX: {}", certs.len());
            }
        }
    }
}

#[test]
fn test_check_for_updates_runs() {
    let info = certcheck_br::updater::check_for_updates();
    println!("Update info: {:?}", info);
}

#[test]
fn test_find_local_certificates() {
    let certs = certcheck_br::gui::certificates::find_local_certificates();
    println!("Certificados locais encontrados: {}", certs.len());
    for c in &certs {
        println!("  - {:?}", c.file_name().unwrap());
    }
    assert!(certs.len() >= 4, "Deve encontrar pelo menos os 4 arquivos de teste na raiz");
}

#[test]
fn test_simulate_load_certificate_command() {
    let certs = certcheck_br::gui::certificates::find_local_certificates();
    for path in certs {
        println!("\nTesting path: {:?}", path);
        let bytes = std::fs::read(&path).expect("read failed");
        let res = certcheck_br::certificate::windows_store::import_pfx_certificates(
            &bytes,
            None,
            &path.display().to_string(),
        );
        match res {
            Ok(c_list) => {
                println!("SUCCESS: imported {} certs from {:?}", c_list.len(), path.file_name().unwrap());
                for c in &c_list {
                    println!("  Cert ID: {} | CN: {} | has_pk: {}", c.id, c.subject.clean_name(), c.has_private_key);
                }
            }
            Err(e) => {
                println!("ERROR: failed to import {:?}: {:?}", path.file_name().unwrap(), e);
                panic!("Failed to import {:?}", path);
            }
        }
    }
}

#[test]
fn test_app_load_local_certs_in_gui_state() {
    let log_buffer = std::sync::Arc::new(certcheck_br::logging::MemoryLogBuffer::new(100));
    let mut state = certcheck_br::app::AppState::new(log_buffer);
    let (cmd_tx, _cmd_rx) = crossbeam_channel::unbounded();

    let local_certs = certcheck_br::gui::certificates::find_local_certificates();
    assert!(!local_certs.is_empty());

    // Simula o clique em carregar o primeiro certificado
    let p = &local_certs[0];
    let bytes = std::fs::read(p).unwrap();
    let certs = certcheck_br::certificate::windows_store::import_pfx_certificates(&bytes, None, &p.display().to_string()).unwrap();
    for cert in certs {
        let id = cert.id.clone();
        state.certificates.retain(|c| c.id != id);
        state.certificates.push(cert);
        state.selected_cert_id = Some(id);
    }

    assert!(!state.certificates.is_empty());
    assert!(state.selected_certificate().is_some());

    // Agora testa se a interface renderiza sem pânico
    let ctx = egui::Context::default();
    let _ = ctx.run(Default::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            certcheck_br::gui::details::render_certificate_details(ui, &mut state, &cmd_tx);
        });
        egui::SidePanel::left("sidebar").show(ctx, |ui| {
            certcheck_br::gui::certificates::render_certificates_sidebar(ui, &mut state, &cmd_tx);
        });
    });

    println!("GUI renderizou com sucesso! Cert selecionado: {:?}", state.selected_certificate().unwrap().subject.clean_name());
}

#[test]
fn test_raw_der_presence_and_windows_viewer() {
    let local_certs = certcheck_br::gui::certificates::find_local_certificates();
    assert!(!local_certs.is_empty());

    let p = &local_certs[0];
    let bytes = std::fs::read(p).unwrap();
    let certs = certcheck_br::certificate::windows_store::import_pfx_certificates(&bytes, None, &p.display().to_string()).unwrap();
    assert!(!certs.is_empty());

    for c in &certs {
        assert!(!c.raw_der.is_empty(), "raw_der deve estar preenchido para o certificado {}", c.id);
        // Garante que o cabeçalho DER ASN.1 SEQUENCE (0x30) está presente
        assert_eq!(c.raw_der[0], 0x30, "Certificado DER deve iniciar com tag SEQUENCE (0x30)");
    }
}



