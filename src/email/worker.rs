use std::time::Duration;

use crate::email::smtp_sender::SmtpSender;
use crate::repositories::email_queue::EmailQueueRepository;

pub async fn run_email_worker(repo: EmailQueueRepository, sender: Option<SmtpSender>) {
    let sender = match sender {
        Some(s) => s,
        None => {
            tracing::warn!("SMTP not configured — email worker disabled");
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.tick().await; // skip first immediate tick

    loop {
        interval.tick().await;

        let pending = match repo.fetch_pending(10).await {
            Ok(emails) => emails,
            Err(e) => {
                tracing::error!("Failed to fetch pending emails: {e}");
                continue;
            }
        };

        for email in pending {
            match sender.send(&email.recipient, &email.subject, &email.body_html).await {
                Ok(()) => {
                    if let Err(e) = repo.mark_sent(&email.id).await {
                        tracing::error!("Failed to mark email {} as sent: {e}", email.id);
                    } else {
                        tracing::info!("Email sent to {}", email.recipient);
                    }
                }
                Err(e) => {
                    tracing::warn!("Email to {} failed: {e}", email.recipient);
                    if let Err(db_err) = repo.mark_failed(&email.id, &e, email.retry_count).await {
                        tracing::error!("Failed to mark email {} as failed: {db_err}", email.id);
                    }
                }
            }
        }
    }
}
