//! Emails the "new Microsynth files" report (and the kansasii-complex alignment PDF) over SMTP.
//!
//! Settings live in [`TBConfig`](crate::config::TBConfig) (`smtp_*`, `email_*`); the SMTP
//! password is kept in the OS keyring ([`load_password`] / [`store_password`]), never in the
//! cosmic config or the logs.

use anyhow::Context;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

/// Keyring service name under which the SMTP password is stored.
const KEYRING_SERVICE: &str = "cosmic-files-smtp";
/// Port that uses implicit TLS; every other port uses STARTTLS.
const SMTPS_PORT: u16 = 465;

/// What [`send_report_email`] needs from the config.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EmailConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from: String,
    /// Comma-separated recipient addresses.
    pub to: String,
}

impl EmailConfig {
    pub fn from_tb_config(c: &crate::config::TBConfig) -> Self {
        Self {
            host: c.smtp_host.trim().to_string(),
            port: c.smtp_port,
            username: c.smtp_username.trim().to_string(),
            from: c.email_from.trim().to_string(),
            to: c.email_to.trim().to_string(),
        }
    }

    /// `true` when host, sender and at least one recipient are set.
    pub fn is_configured(&self) -> bool {
        !self.host.is_empty() && !self.from.is_empty() && self.recipients().next().is_some()
    }

    fn recipients(&self) -> impl Iterator<Item = &str> {
        self.to.split(',').map(str::trim).filter(|s| !s.is_empty())
    }
}

/// Reads the SMTP password for `username` from the OS keyring.
pub fn load_password(username: &str) -> Option<String> {
    if username.is_empty() {
        return None;
    }
    keyring::Entry::new(KEYRING_SERVICE, username)
        .and_then(|e| e.get_password())
        .map_err(|e| {
            if !matches!(e, keyring::Error::NoEntry) {
                log::warn!("email: keyring read failed: {e}");
            }
        })
        .ok()
        .filter(|p| !p.is_empty())
}

/// Stores the SMTP password for `username` in the OS keyring.
pub fn store_password(username: &str, password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!username.is_empty(), "SMTP username is empty");
    keyring::Entry::new(KEYRING_SERVICE, username)?.set_password(password)?;
    Ok(())
}

/// Builds the message: a plain-text body and one PDF attachment per `(file name, bytes)`.
fn build_message(
    cfg: &EmailConfig,
    subject: &str,
    body: &str,
    attachments: Vec<(String, Vec<u8>)>,
) -> anyhow::Result<Message> {
    let mut builder = Message::builder()
        .from(cfg.from.parse::<Mailbox>().context("invalid sender address")?)
        .subject(subject);
    for to in cfg.recipients() {
        builder = builder.to(to
            .parse::<Mailbox>()
            .with_context(|| format!("invalid recipient address {to:?}"))?);
    }
    let mut parts = MultiPart::mixed().singlepart(SinglePart::plain(body.to_string()));
    let pdf = ContentType::parse("application/pdf").context("content type")?;
    for (name, bytes) in attachments {
        parts = parts.singlepart(Attachment::new(name).body(bytes, pdf.clone()));
    }
    builder.multipart(parts).context("building message")
}

/// Sends the PDFs by email. Blocking (SMTP over a synchronous transport): call it from
/// `tokio::task::spawn_blocking`.
pub fn send_report_email(
    cfg: &EmailConfig,
    password: &str,
    subject: &str,
    body: &str,
    attachments: Vec<(String, Vec<u8>)>,
) -> anyhow::Result<()> {
    anyhow::ensure!(cfg.is_configured(), "email is not configured");
    let message = build_message(cfg, subject, body, attachments)?;
    let transport = if cfg.port == SMTPS_PORT {
        SmtpTransport::relay(&cfg.host)
    } else {
        SmtpTransport::starttls_relay(&cfg.host)
    }
    .context("connecting to SMTP server")?
    .port(cfg.port);
    let transport = if cfg.username.is_empty() {
        transport
    } else {
        transport.credentials(Credentials::new(cfg.username.clone(), password.to_string()))
    };
    transport.build().send(&message).context("sending email")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> EmailConfig {
        EmailConfig {
            host: "smtp.example.org".into(),
            port: 587,
            username: "u".into(),
            from: "Lab <lab@example.org>".into(),
            to: "a@example.org, b@example.org ,".into(),
        }
    }

    #[test]
    fn configured_needs_host_sender_and_recipient() {
        assert!(cfg().is_configured());
        assert!(!EmailConfig::default().is_configured());
        assert!(!EmailConfig { to: " , ".into(), ..cfg() }.is_configured());
        assert!(!EmailConfig { host: String::new(), ..cfg() }.is_configured());
    }

    #[test]
    fn message_has_all_recipients_and_pdf_attachments() {
        let msg = build_message(
            &cfg(),
            "New AB1 files",
            "body",
            vec![
                ("a.pdf".into(), b"%PDF-1".to_vec()),
                ("b.pdf".into(), b"%PDF-2".to_vec()),
            ],
        )
        .unwrap();
        let raw = String::from_utf8_lossy(&msg.formatted()).into_owned();
        assert!(raw.contains("a@example.org"));
        assert!(raw.contains("b@example.org"));
        assert!(raw.contains("filename=\"a.pdf\""));
        assert!(raw.contains("filename=\"b.pdf\""));
        assert!(raw.contains("application/pdf"));
    }

    #[test]
    fn invalid_recipient_is_an_error() {
        let c = EmailConfig { to: "not an address".into(), ..cfg() };
        assert!(build_message(&c, "s", "b", Vec::new()).is_err());
    }
}
