//! Gerador de Laudo Técnico Formal em HTML para impressão e documentação de suporte de TI.

use crate::report::DiagnosticReport;
use crate::validation::CheckStatus;

/// Gera um documento HTML completo e estilizado para visualização e impressão de Laudo Técnico.
pub fn generate_html_report(report: &DiagnosticReport) -> String {
    let cert = &report.certificate;
    let val = &report.validation;
    let rev = &report.revocation;

    let overall_badge = match val.overall_status {
        Some(crate::validation::OverallStatus::AptoParaUso) => {
            r#"<span class="badge pass">APTO PARA USO</span>"#
        }
        Some(crate::validation::OverallStatus::ComRestricoes) => {
            r#"<span class="badge warn">COM RESTRIÇÕES</span>"#
        }
        Some(crate::validation::OverallStatus::Inapto) => {
            r#"<span class="badge fail">INAPTO / INVÁLIDO</span>"#
        }
        _ => r#"<span class="badge info">NÃO VERIFICADO</span>"#,
    };

    let mut checks_html = String::new();
    for c in &val.checks {
        let (status_class, status_label) = match c.status {
            CheckStatus::Pass => ("pass", "APROVADO"),
            CheckStatus::Warning => ("warn", "AVISO"),
            CheckStatus::Error => ("fail", "FALHA"),
            CheckStatus::Info => ("info", "INFO"),
            _ => ("neutral", "N/A"),
        };

        let detail_text = c.technical_details.as_deref().unwrap_or("");
        checks_html.push_str(&format!(
            r#"<tr>
                <td><strong>{}</strong><br><span class="desc">{}</span></td>
                <td><span class="status-pill {}">{}</span></td>
                <td>{}</td>
            </tr>"#,
            c.name, c.message, status_class, status_label, detail_text
        ));
    }

    let mut a3_html = String::new();
    if let Some(ref a3) = report.a3_diagnostics {
        let mut readers_str = String::new();
        if a3.readers.is_empty() {
            readers_str = "<li>Nenhum leitor PC/SC detectado no momento do teste.</li>".to_string();
        } else {
            for r in &a3.readers {
                readers_str.push_str(&format!(
                    "<li><strong>{}</strong> — {} (ATR: {})</li>",
                    r.name,
                    r.status,
                    r.card_atr_hex.as_deref().unwrap_or("Não disponível")
                ));
            }
        }

        a3_html = format!(
            r#"<div class="card">
                <h3>🔍 Diagnóstico de Hardware A3 e Subsistema PC/SC</h3>
                <ul>{}</ul>
            </div>"#,
            readers_str
        );
    }

    let cpf_cnpj = cert
        .identity
        .cnpj
        .as_deref()
        .or(cert.identity.cpf.as_deref())
        .unwrap_or("Não identificado");

    let legal_rep = cert
        .identity
        .legal_representative()
        .unwrap_or("—");

    let a1_a3 = if cert.cert_type == crate::certificate::CertificateType::A3 || cert.is_hardware_backed {
        "A3 (Hardware / Smart Card / Token)"
    } else {
        "A1 (Arquivo / Software)"
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Laudo Técnico - CertCheck BR - {}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8fafc;
            color: #1e293b;
            margin: 0;
            padding: 24px;
            font-size: 13.5px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            padding: 32px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0284c7;
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 22px;
            color: #0369a1;
        }}
        .header .meta {{
            font-size: 12px;
            color: #64748b;
            text-align: right;
        }}
        .card {{
            background: #f1f5f9;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 20px;
        }}
        .card h3 {{
            margin-top: 0;
            margin-bottom: 12px;
            font-size: 15px;
            color: #0f172a;
            border-bottom: 1px solid #cbd5e1;
            padding-bottom: 6px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
        }}
        .grid-item strong {{
            color: #475569;
            display: block;
            font-size: 11.5px;
            text-transform: uppercase;
        }}
        .grid-item span {{
            font-size: 14px;
            font-weight: 600;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
        }}
        th, td {{
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }}
        th {{
            background: #e2e8f0;
            font-size: 12px;
            text-transform: uppercase;
            color: #334155;
        }}
        .desc {{
            font-size: 12px;
            color: #64748b;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
        }}
        .status-pill {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
        .pass {{ background: #dcfce7; color: #15803d; }}
        .warn {{ background: #fef9c3; color: #a16207; }}
        .fail {{ background: #fee2e2; color: #b91c1c; }}
        .info {{ background: #e0f2fe; color: #0369a1; }}
        .neutral {{ background: #f1f5f9; color: #475569; }}
        .footer {{
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            color: #64748b;
            font-size: 11px;
        }}
        .signature-box {{
            margin-top: 40px;
            padding-top: 8px;
            border-top: 1px dashed #94a3b8;
            width: 280px;
            text-align: center;
        }}
        @media print {{
            body {{ background: #ffffff; padding: 0; }}
            .container {{ box-shadow: none; padding: 0; }}
            .no-print {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡 Laudo Técnico de Diagnóstico Digital</h1>
                <div style="font-size: 13px; color: #64748b; margin-top: 4px;">Padrão ICP-Brasil • Validação X.509 RFC 5280 • Auditoria de Hardware A1/A3</div>
            </div>
            <div class="meta">
                <div><strong>Emissão do Laudo:</strong> {}</div>
                <div><strong>CertCheck BR:</strong> v{}</div>
                <div style="margin-top: 6px;">Veredito: {}</div>
            </div>
        </div>

        <div class="card">
            <h3>👤 Identificação do Titular e Metadados</h3>
            <div class="grid">
                <div class="grid-item">
                    <strong>Titular / Razão Social:</strong>
                    <span>{}</span>
                </div>
                <div class="grid-item">
                    <strong>CPF / CNPJ:</strong>
                    <span>{}</span>
                </div>
                <div class="grid-item">
                    <strong>Responsável Legal:</strong>
                    <span>{}</span>
                </div>
                <div class="grid-item">
                    <strong>Tipo de Certificado:</strong>
                    <span>{}</span>
                </div>
                <div class="grid-item">
                    <strong>Autoridade Emissora (AC):</strong>
                    <span>{}</span>
                </div>
                <div class="grid-item">
                    <strong>Número de Série:</strong>
                    <span style="font-family: monospace; font-size: 12px;">{}</span>
                </div>
                <div class="grid-item">
                    <strong>Início de Vigência:</strong>
                    <span>{}</span>
                </div>
                <div class="grid-item">
                    <strong>Data de Expiração:</strong>
                    <span>{}</span>
                </div>
            </div>
        </div>

        {}

        <div class="card" style="padding: 0; overflow: hidden; background: #ffffff;">
            <div style="padding: 12px 16px; background: #f8fafc; border-bottom: 1px solid #e2e8f0;">
                <h3 style="margin: 0; border: none; padding: 0;">📋 Checklist de Conformidade Técnica X.509 e ICP-Brasil</h3>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 40%;">Item Avaliado</th>
                        <th style="width: 15%;">Resultado</th>
                        <th style="width: 45%;">Detalhamento Normativo</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h3>🌐 Verificação de Revogação Online (CRL e OCSP)</h3>
            <p><strong>Status Consolidado de Revogação:</strong> {}</p>
            <p class="desc">As listas de certificados revogados (CRL) e respondedores OCSP da Autoridade Certificadora foram consultados em tempo real via HTTP seguro.</p>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-top: 32px;">
            <div class="signature-box">
                <div style="font-size: 12px; font-weight: 600;">Responsável Técnico / Suporte de TI</div>
                <div style="font-size: 11px; color: #64748b;">Assinatura / Visto</div>
            </div>
            <div style="text-align: right;">
                <button class="no-print" onclick="window.print()" style="background: #0284c7; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer;">
                    🖨 Imprimir ou Salvar em PDF
                </button>
            </div>
        </div>

        <div class="footer">
            <div>Documento gerado automaticamente pelo CertCheck BR — Ferramenta Técnica de Diagnóstico ICP-Brasil</div>
            <div>https://github.com/leandrop2103/certcheck-br</div>
        </div>
    </div>
</body>
</html>"#,
        cert.subject.clean_name(),
        report.generated_at.format("%d/%m/%Y às %H:%M:%S UTC"),
        report.app_version,
        overall_badge,
        cert.subject.clean_name(),
        cpf_cnpj,
        legal_rep,
        a1_a3,
        cert.issuer.clean_name(),
        cert.serial_number_hex,
        cert.not_before.format("%d/%m/%Y %H:%M:%S"),
        cert.not_after.format("%d/%m/%Y %H:%M:%S"),
        a3_html,
        checks_html,
        rev.final_status.map(|s| s.to_string()).unwrap_or_else(|| "NÃO VERIFICADO".to_string())
    )
}
