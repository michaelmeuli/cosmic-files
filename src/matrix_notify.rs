use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn encode_room_id(room_id: &str) -> String {
    room_id
        .chars()
        .map(|c| match c {
            '!' => "%21".to_string(),
            ':' => "%3A".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn txn_id() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}

/// Upload `csv_path` to the Matrix homeserver and send it as an `m.file` event to `room_id`.
///
/// Requires `matrix_homeserver` (e.g. `"https://matrix.example.org"`), a valid
/// `access_token`, and a `room_id` in the form `"!localpart:server"`.
///
/// Uses the stable Matrix v3 media endpoint (`/_matrix/media/v3/upload`). Some homeservers
/// running Matrix spec ≥ 1.11 have migrated authenticated media to
/// `/_matrix/client/v1/media/upload`; if upload returns 404 or 401, that endpoint may be
/// needed instead.
pub async fn send_csv_to_matrix(
    homeserver: &str,
    access_token: &str,
    room_id: &str,
    csv_path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filename = csv_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("report.csv");

    let bytes = tokio::fs::read(csv_path).await?;
    let size = bytes.len();

    let client = reqwest::Client::new();

    // --- Upload ---
    let upload_url = format!(
        "{}/_matrix/media/v3/upload?filename={}",
        homeserver.trim_end_matches('/'),
        filename
    );
    let upload_resp: serde_json::Value = client
        .put(&upload_url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "text/csv")
        .body(bytes)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let content_uri = upload_resp["content_uri"]
        .as_str()
        .ok_or("Matrix upload response missing content_uri")?;

    // --- Send m.file event ---
    let send_url = format!(
        "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
        homeserver.trim_end_matches('/'),
        encode_room_id(room_id),
        txn_id()
    );
    let body = serde_json::json!({
        "msgtype": "m.file",
        "body": filename,
        "url": content_uri,
        "info": {
            "mimetype": "text/csv",
            "size": size
        }
    });
    client
        .put(&send_url)
        .header("Authorization", format!("Bearer {access_token}"))
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}
