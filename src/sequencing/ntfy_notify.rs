//! Batch-scan completion notifications via [ntfy](https://ntfy.sh/).

/// Push `pdf_bytes` to an ntfy topic as a PDF file attachment.
///
/// `topic` may be a bare topic name (sent to `https://ntfy.sh/{topic}`) or a full URL.
///
/// The report lists lab numbers and resistance calls. On the public ntfy.sh server anyone who
/// knows or guesses the topic name can read it, so a bare topic logs a warning; a self-hosted
/// server URL (or an access-controlled one) avoids that.
pub async fn send_report_ntfy(
    topic: &str,
    pdf_bytes: Vec<u8>,
    n_records: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = if topic.starts_with("http://") || topic.starts_with("https://") {
        topic.to_string()
    } else {
        log::warn!(
            "ntfy: sending the report to the public server ntfy.sh, where anyone who knows the \
             topic name can read it; set a full URL of a private server to avoid this"
        );
        format!("https://ntfy.sh/{topic}")
    };
    if url.starts_with("http://") {
        log::warn!("ntfy: {url} is unencrypted http; the report is sent in clear text");
    }

    reqwest::Client::new()
        .put(&url)
        .header("Content-Type", "application/pdf")
        .header("Filename", "ab1_susceptibility_report.pdf")
        .header("Title", format!("AB1 scan complete ({n_records} records)"))
        .body(pdf_bytes)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}
