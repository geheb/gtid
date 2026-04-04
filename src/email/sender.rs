use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::AppConfig;

pub struct SmtpSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpSender {
    pub fn new(config: &AppConfig) -> Option<Self> {
        let host = config.smtp_host.as_deref()?;

        let mut builder = if config.smtp_starttls {
            match AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host) {
                Ok(b) => b.port(config.smtp_port),
                Err(e) => {
                    tracing::error!("Failed to create SMTP transport: {e}");
                    return None;
                }
            }
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
                .port(config.smtp_port)
        };

        if let (Some(user), Some(pass)) = (&config.smtp_username, &config.smtp_password) {
            builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
        }

        let from: Mailbox = config.smtp_from.parse().unwrap_or_else(|_| {
            tracing::warn!("Invalid SMTP_FROM '{}', falling back to noreply@localhost", config.smtp_from);
            "noreply@localhost".parse().unwrap()
        });

        Some(Self {
            transport: builder.build(),
            from,
        })
    }

    pub async fn send(&self, recipient: &str, subject: &str, body_html: &str) -> Result<(), String> {
        let to: Mailbox = recipient.parse().map_err(|e| format!("Invalid recipient: {e}"))?;

        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body_html.to_string())
            .map_err(|e| format!("Failed to build email: {e}"))?;

        self.transport
            .send(message)
            .await
            .map_err(|e| format!("SMTP send failed: {e}"))?;

        Ok(())
    }
}
