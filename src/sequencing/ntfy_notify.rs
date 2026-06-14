/// Push `pdf_bytes` to an ntfy topic as a PDF file attachment.
///
/// `topic` may be a bare topic name (sent to `https://ntfy.sh/{topic}`) or a full URL.
pub async fn send_report_ntfy(
    topic: &str,
    pdf_bytes: Vec<u8>,
    n_records: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = if topic.starts_with("http://") || topic.starts_with("https://") {
        topic.to_string()
    } else {
        format!("https://ntfy.sh/{topic}")
    };

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
