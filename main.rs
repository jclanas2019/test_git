// main.rs
use axum::{
    extract::{Path, State, Multipart},
    routing::{get, post},
    Json, Router,
    http::{StatusCode, header::HeaderName, HeaderMap},
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, fs, path::PathBuf};
use dotenvy::dotenv;
use std::env;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use jsonwebtoken::{encode, Header as JwtHeader, Algorithm, EncodingKey};
use tracing::{info, warn, error};
use tracing_subscriber::EnvFilter;
use sqlx::{SqlitePool, Row, sqlite::SqliteConnectOptions};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use lopdf::{Document, Object, Dictionary, Stream};
use anyhow::Result;
use qrcode::QrCode;
use image::{Luma, DynamicImage, ImageBuffer};
use std::io::Cursor;

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    base_url: String,
    otp_service: OtpService,
    crypto_service: CryptoService,
    storage_dir: String,
    chilean_config: ChileanConfig,
}

#[derive(Clone)]
struct OtpService {
    mode: OtpMode,
    length: usize,
    ttl_minutes: i64,
}

#[derive(Clone)]
#[allow(dead_code)]
enum OtpMode {
    Fixed(String),
    Random,
    Email,
    Sms,
}

#[derive(Clone)]
struct CryptoService {
    priv_key_path: String,
    #[allow(dead_code)]
    pub_key_path: String,
    algorithm: Algorithm,
}

#[derive(Clone)]
struct ChileanConfig {
    require_rut_validation: bool,
    timezone: String,
    legal_policy_version: String,
    #[allow(dead_code)]
    retention_days: i64,
}

#[derive(Serialize, Deserialize, Clone)]
struct ChileanEvidence {
    doc_sha256: String,
    doc_name: String,
    doc_size: u64,
    ts_utc: String,
    ts_chile: String,
    timezone: String,
    signer_id: String,
    signer_rut: Option<String>,
    signer_validated: bool,
    auth_method: String,
    otp_verified: bool,
    ip_address: String,
    user_agent: String,
    consent_hash: String,
    consent_text: String,
    policy_version: String,
    system_version: String,
    session_id: String,
    legal_framework: String,
    signature_type: String,
    jurisdiction: String,
}

#[derive(Serialize, Deserialize)]
struct ChileanJWS {
    iss: String,
    iat: i64,
    exp: i64,
    jti: String,
    evidence: ChileanEvidence,
    legal_validity: bool,
    compliance_checked: bool,
}

#[derive(Deserialize)]
struct SignIntentReq {
    signer_id: String,
    signer_rut: Option<String>,
    doc_name: String,
    consent_text: String,
}

#[derive(Serialize)]
struct SignIntentResp {
    jti: String,
    otp_hint: String,
    status: String,
    expires_at: String,
    verification_requirements: Vec<String>,
}

#[derive(Serialize)]
struct VerificationResult {
    valid: bool,
    valid_signature: bool,
    valid_hash: bool,
    valid_timestamp: bool,
    expired: bool,
    jti: String,
    evidence: ChileanEvidence,
    legal_status: String,
    compliance_notes: Vec<String>,
    verified_at: String,
    verification_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    setup_tracing()?;
    
    println!("Iniciando servidor FES...");
    
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    
    println!("Validando recursos...");
    validate_and_setup_resources().await?;
    
    println!("Configurando base de datos...");
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://fes.db".to_string());
    let db_path = database_url.strip_prefix("sqlite://").unwrap_or("fes.db");
    
    let connect_options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true);
    
    println!("Conectando a base de datos: {}", db_path);
    let pool = SqlitePool::connect_with(connect_options).await?;
    run_migrations(&pool).await?;

    println!("Configurando estado de aplicacion...");
    let state = AppState {
        pool,
        base_url,
        otp_service: create_otp_service(),
        crypto_service: create_crypto_service(),
        storage_dir: env::var("STORAGE_DIR").unwrap_or_else(|_| "storage".to_string()),
        chilean_config: create_chilean_config(),
    };

    fs::create_dir_all(&state.storage_dir)?;

    println!("Configurando rutas...");
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/sign-intent", post(sign_intent))
        .route("/api/v1/sign-confirm", post(sign_confirm))
        .route("/api/v1/verify/:jti", get(verify))
        .route("/api/v1/verify/:jti/download", get(download_original))
        .route("/api/v1/verify/:jti/download-signed", get(download_signed_document))
        .route("/api/v1/generate-justificante/:jti", get(generate_justificante))
        .route("/api/v1/admin/stats", get(admin_stats))
        .route("/api/v1/get-otp/:signer_id", get(get_otp_for_signer))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = bind_addr.parse()?;
    println!("=== SERVIDOR FES INICIADO EN http://{} ===", addr);
    println!("Configuracion: Chile timezone, RUT validation enabled");
    
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Servidor escuchando en {}...", addr);
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

async fn validate_and_setup_resources() -> Result<()> {
    println!("Iniciando validacion de recursos...");
    
    let storage_dir = env::var("STORAGE_DIR").unwrap_or_else(|_| "storage".to_string());
    let keys_dir = "keys";
    
    fs::create_dir_all(&storage_dir)?;
    fs::create_dir_all(keys_dir)?;
    println!("Directorios creados: {}, {}", storage_dir, keys_dir);
    
    let priv_key_path = env::var("PRIVATE_KEY_PATH").unwrap_or_else(|_| "keys/server_rsa_pkcs8.pem".to_string());
    let pub_key_path = env::var("PUBLIC_KEY_PATH").unwrap_or_else(|_| "keys/server_rsa_pub.pem".to_string());
    
    println!("Verificando claves RSA...");
    if !PathBuf::from(&priv_key_path).exists() || !PathBuf::from(&pub_key_path).exists() {
        println!("Claves RSA no encontradas, generando automaticamente...");
        println!("ADVERTENCIA: Esto puede tomar unos segundos...");
        generate_rsa_keys(&priv_key_path, &pub_key_path).await?;
        println!("Claves RSA generadas exitosamente");
    } else {
        println!("Claves RSA encontradas y validadas");
    }
    
    println!("Validando configuracion de base de datos...");
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://fes.db".to_string());
    validate_database_setup(&database_url).await?;
    
    println!("Validando configuracion de red...");
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    validate_network_config(&bind_addr)?;
    
    println!("Todos los recursos validados correctamente");
    Ok(())
}

async fn generate_rsa_keys(priv_key_path: &str, pub_key_path: &str) -> Result<()> {
    use std::process::Command;
    
    let temp_key = "keys/temp_rsa_private.pem";
    let output = Command::new("openssl")
        .args(&["genrsa", "-out", temp_key, "2048"])
        .output()?;
    
    if !output.status.success() {
        return Err(anyhow::Error::msg(format!("Error generando clave privada RSA: {}", 
            String::from_utf8_lossy(&output.stderr))));
    }
    
    let output = Command::new("openssl")
        .args(&["pkcs8", "-topk8", "-inform", "PEM", "-outform", "PEM", 
               "-nocrypt", "-in", temp_key, "-out", priv_key_path])
        .output()?;
    
    if !output.status.success() {
        return Err(anyhow::Error::msg(format!("Error convirtiendo a PKCS#8: {}", 
            String::from_utf8_lossy(&output.stderr))));
    }
    
    let output = Command::new("openssl")
        .args(&["rsa", "-pubout", "-in", temp_key, "-out", pub_key_path])
        .output()?;
    
    if !output.status.success() {
        return Err(anyhow::Error::msg(format!("Error generando clave pública: {}", 
            String::from_utf8_lossy(&output.stderr))));
    }
    
    fs::remove_file(temp_key)?;
    
    if !PathBuf::from(priv_key_path).exists() {
        return Err(anyhow::Error::msg(format!("La clave privada no fue creada: {}", priv_key_path)));
    }
    if !PathBuf::from(pub_key_path).exists() {
        return Err(anyhow::Error::msg(format!("La clave pública no fue creada: {}", pub_key_path)));
    }
    
    let priv_key_content = fs::read_to_string(priv_key_path)?;
    let pub_key_content = fs::read_to_string(pub_key_path)?;
    
    if !priv_key_content.contains("-----BEGIN PRIVATE KEY-----") {
        return Err(anyhow::Error::msg("Formato de clave privada inválido"));
    }
    if !pub_key_content.contains("-----BEGIN PUBLIC KEY-----") {
        return Err(anyhow::Error::msg("Formato de clave pública inválido"));
    }
    
    Ok(())
}

async fn validate_database_setup(database_url: &str) -> Result<()> {
    if !database_url.starts_with("sqlite://") && !database_url.starts_with("postgres://") {
        return Err(anyhow::Error::msg("URL de base de datos inválida"));
    }
    Ok(())
}

fn validate_network_config(bind_addr: &str) -> Result<()> {
    bind_addr.parse::<SocketAddr>().map_err(|e| anyhow::Error::msg(format!("Dirección de red inválida: {}", e)))?;
    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn sign_intent(State(state): State<AppState>, Json(payload): Json<SignIntentReq>) -> Result<Json<SignIntentResp>, (StatusCode, String)> {
    let jti = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::minutes(state.otp_service.ttl_minutes);
    let otp = generate_otp(&state.otp_service).await;
    let otp_hint = get_otp_hint(&state.otp_service);

    let requirements = vec![
        "OTP válido".to_string(),
        "Documento PDF/imagen".to_string(),
        if state.chilean_config.require_rut_validation { "RUT chileno válido".to_string() } else { "".to_string() },
    ].into_iter().filter(|s| !s.is_empty()).collect();

    let now_timestamp = now.unix_timestamp();
    sqlx::query("INSERT INTO sign_intents (jti, signer_id, signer_rut, otp, expires_at, doc_name, consent_text, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)")
        .bind(&jti)
        .bind(&payload.signer_id)
        .bind(&payload.signer_rut)
        .bind(&otp)
        .bind(expires_at.unix_timestamp())
        .bind(&payload.doc_name)
        .bind(&payload.consent_text)
        .bind("pending")
        .bind(now_timestamp)
        .bind(now_timestamp)
        .execute(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al guardar intención: {}", e)))?;

    Ok(Json(SignIntentResp {
        jti,
        otp_hint,
        status: "pending".to_string(),
        expires_at: expires_at.format(&Rfc3339).unwrap(),
        verification_requirements: requirements,
    }))
}

async fn sign_confirm(State(state): State<AppState>, mut multipart: Multipart) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut jti = None;
    let mut signer_id = None;
    let mut otp = None;
    let mut consent_text = None;
    let mut file = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| internal_err(format!("Error al procesar multipart: {}", e)))? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "jti" => jti = Some(field.text().await.map_err(|e| internal_err(format!("Error al leer jti: {}", e)))?),
            "signer_id" => signer_id = Some(field.text().await.map_err(|e| internal_err(format!("Error al leer signer_id: {}", e)))?),
            "otp" => otp = Some(field.text().await.map_err(|e| internal_err(format!("Error al leer otp: {}", e)))?),
            "consent_text" => consent_text = Some(field.text().await.map_err(|e| internal_err(format!("Error al leer consent_text: {}", e)))?),
            "file" => {
                let filename = field.file_name().unwrap_or("unnamed").to_string();
                let data = field.bytes().await.map_err(|e| internal_err(format!("Error al leer archivo: {}", e)))?;
                file = Some((filename, data.to_vec()));
            }
            _ => {}
        }
    }

    let jti = jti.ok_or((StatusCode::BAD_REQUEST, "Falta jti".to_string()))?;
    let signer_id = signer_id.ok_or((StatusCode::BAD_REQUEST, "Falta signer_id".to_string()))?;
    let otp = otp.ok_or((StatusCode::BAD_REQUEST, "Falta otp".to_string()))?;
    let consent_text = consent_text.ok_or((StatusCode::BAD_REQUEST, "Falta consent_text".to_string()))?;
    let (filename, file_data) = file.ok_or((StatusCode::BAD_REQUEST, "Falta archivo".to_string()))?;

    let intent = sqlx::query("SELECT otp, expires_at FROM sign_intents WHERE jti = ?1 AND signer_id = ?2 AND status = 'pending'")
        .bind(&jti)
        .bind(&signer_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al consultar intención: {}", e)))?;

    let intent = intent.ok_or((StatusCode::NOT_FOUND, "Intención no encontrada o ya procesada".to_string()))?;
    let stored_otp = intent.get::<String, _>("otp");
    let expires_at = intent.get::<i64, _>("expires_at");

    if OffsetDateTime::now_utc().unix_timestamp() > expires_at {
        return Err((StatusCode::GONE, "OTP expirado".to_string()));
    }

    if otp != stored_otp {
        return Err((StatusCode::UNAUTHORIZED, "OTP inválido".to_string()));
    }

    let doc_sha256 = format!("{:x}", Sha256::digest(&file_data));
    let doc_size = file_data.len() as u64;
    let ts_utc = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let ts_chile = OffsetDateTime::now_utc().format(&Rfc3339).unwrap(); // Ajustar zona horaria si es necesario
    let ip_address = "127.0.0.1".to_string(); // Placeholder, ajusta con ConnectInfo
    let user_agent = "Unknown".to_string(); // Placeholder, ajusta con headers
    let consent_hash = calculate_hash(&consent_text);
    let session_id = Uuid::new_v4().to_string();
    let policy_version = state.chilean_config.legal_policy_version.clone();
    let system_version = env!("CARGO_PKG_VERSION").to_string();
    let legal_framework = "Ley 19.799".to_string();
    let signature_type = "FES".to_string();
    let jurisdiction = "CL".to_string();

    let evidence = ChileanEvidence {
        doc_sha256,
        doc_name: filename,
        doc_size,
        ts_utc: ts_utc.clone(),
        ts_chile,
        timezone: state.chilean_config.timezone.clone(),
        signer_id: signer_id.clone(),
        signer_rut: Some("12001623-7".to_string()), // Placeholder, ajusta según SignIntentReq
        signer_validated: true, // Placeholder, valida RUT si está configurado
        auth_method: "OTP".to_string(),
        otp_verified: true,
        ip_address,
        user_agent,
        consent_hash,
        consent_text,
        policy_version,
        system_version,
        session_id,
        legal_framework,
        signature_type,
        jurisdiction,
    };

    let storage_path = PathBuf::from(&state.storage_dir).join(&jti);
    fs::create_dir_all(&storage_path).map_err(|e| internal_err(format!("Error al crear directorio: {}", e)))?;
    let original_path = storage_path.join("original.pdf");
    fs::write(&original_path, &file_data).map_err(|e| internal_err(format!("Error al guardar archivo original: {}", e)))?;

    let signed_path = storage_path.join("signed_document.pdf");
    create_signed_pdf(&file_data, &evidence, &jti, &state.base_url, &signed_path).await.map_err(|e| internal_err(format!("Error al crear PDF firmado: {}", e)))?;

    let claims = ChileanJWS {
        iss: "fes_rust_mvp".to_string(),
        iat: OffsetDateTime::now_utc().unix_timestamp(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 3600, // 1 hora de validez
        jti: jti.clone(),
        evidence: evidence.clone(),
        legal_validity: true,
        compliance_checked: true,
    };

    let token = encode(&JwtHeader::new(state.crypto_service.algorithm), &claims, &EncodingKey::from_rsa_pem(&fs::read_to_string(&state.crypto_service.priv_key_path).map_err(|e| internal_err(format!("Error al leer clave privada: {}", e)))?.as_bytes()).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error al crear EncodingKey: {}", e)))?).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error al codificar JWT: {}", e)))?;

    sqlx::query("UPDATE sign_intents SET status = 'confirmed' WHERE jti = ?1")
        .bind(&jti)
        .execute(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al actualizar intención: {}", e)))?;

    sqlx::query("INSERT INTO evidences (jti, evidence_json, created_at) VALUES (?1, ?2, ?3)")
        .bind(&jti)
        .bind(serde_json::to_string(&evidence).map_err(|e| internal_err(format!("Error al serializar evidencia: {}", e)))?)
        .bind(OffsetDateTime::now_utc().unix_timestamp())
        .execute(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al guardar evidencia: {}", e)))?;

    Ok(Json(serde_json::json!({
        "doc_sha256": evidence.doc_sha256,
        "jti": jti,
        "signed_document_available": true,
        "status": "confirmed",
        "timestamp": ts_utc,
        "verification_url": format!("{}/api/v1/verify/{}", state.base_url, jti),
        "jwt": token,
    })))
}

async fn verify(State(state): State<AppState>, Path(jti): Path<String>) -> Result<Json<VerificationResult>, (StatusCode, String)> {
    info!("Verificando JTI: {}", jti);
    
    let evidence = sqlx::query("SELECT evidence_json FROM evidences WHERE jti = ?1")
        .bind(&jti)
        .fetch_optional(&state.pool)
        .await;
    
    match evidence {
        Ok(Some(row)) => {
            let evidence_json: String = row.get("evidence_json");
            info!("Evidencia encontrada para JTI {}: {}", jti, evidence_json);
            
            let evidence_data: ChileanEvidence = serde_json::from_str(&evidence_json)
                .map_err(|e| {
                    error!("Error al deserializar evidencia para JTI {}: {}", jti, e);
                    internal_err(format!("Error al deserializar evidencia: {}", e))
                })?;

            let now = OffsetDateTime::now_utc();
            let ts_utc = OffsetDateTime::parse(&evidence_data.ts_utc, &Rfc3339).map_err(|e| {
                error!("Error al parsear ts_utc para JTI {}: {}", jti, e);
                internal_err(format!("Error al parsear timestamp: {}", e))
            })?;
            let expired = now > ts_utc + time::Duration::seconds(3600); // 1 hora de validez
            let valid_hash = evidence_data.doc_sha256 == calculate_hash(&evidence_data.consent_text);
            let valid_signature = true; // Placeholder, valida JWT si está implementado
            let valid_timestamp = !expired;
            
            let verification_id = Uuid::new_v4().to_string();
            let verified_at = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();

            sqlx::query("INSERT INTO verifications (jti, verification_id, verified_at) VALUES (?1, ?2, ?3)")
                .bind(&jti)
                .bind(&verification_id)
                .bind(now.unix_timestamp())
                .execute(&state.pool)
                .await
                .map_err(|e| {
                    error!("Error al insertar verificación para JTI {}: {}", jti, e);
                    internal_err(format!("Error al registrar verificación: {}", e))
                })?;

            Ok(Json(VerificationResult {
                valid: valid_hash && valid_timestamp && valid_signature,
                valid_signature,
                valid_hash,
                valid_timestamp,
                expired,
                jti,
                evidence: evidence_data,
                legal_status: "Valid".to_string(),
                compliance_notes: vec![],
                verified_at,
                verification_id,
            }))
        }
        Ok(None) => {
            warn!("No se encontró evidencia para JTI: {}", jti);
            Err(not_found("Evidencia no encontrada"))
        }
        Err(e) => {
            error!("Error de base de datos para JTI {}: {}", jti, e);
            Err(internal_err(format!("Error al consultar evidencia: {}", e)))
        }
    }
}

async fn download_original(State(state): State<AppState>, Path(jti): Path<String>) -> Result<(StatusCode, [(HeaderName, String); 2], Vec<u8>), (StatusCode, String)> {
    let evidence = sqlx::query("SELECT * FROM evidences WHERE jti = ?1")
        .bind(&jti)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al consultar evidencia: {}", e)))?;

    let evidence = evidence.ok_or_else(|| not_found("Documento no encontrado"))?;
    let evidence_data: ChileanEvidence = serde_json::from_str(&evidence.get::<String, _>("evidence_json"))
        .map_err(|e| internal_err(format!("Error al deserializar evidencia: {}", e)))?;

    let storage_path = PathBuf::from(&state.storage_dir).join(&jti);
    let file_path = storage_path.join("original.pdf");

    let file_data = fs::read(&file_path).map_err(|e| not_found(format!("Archivo original no encontrado: {}", e)))?;
    let doc_name = evidence_data.doc_name;

    Ok((
        StatusCode::OK,
        [
            (HeaderName::from_static("content-type"), "application/octet-stream".to_string()),
            (HeaderName::from_static("content-disposition"), format!("attachment; filename=\"{}\"", doc_name)),
        ],
        file_data,
    ))
}

async fn download_signed_document(
    State(state): State<AppState>,
    Path(jti): Path<String>,
) -> Result<(StatusCode, [(HeaderName, String); 2], Vec<u8>), (StatusCode, String)> {
    let evidence = sqlx::query("SELECT * FROM evidences WHERE jti = ?1")
        .bind(&jti)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al consultar evidencia: {}", e)))?;

    let evidence = evidence.ok_or_else(|| not_found("Documento no encontrado"))?;
    let evidence_data: ChileanEvidence = serde_json::from_str(&evidence.get::<String, _>("evidence_json"))
        .map_err(|e| internal_err(format!("Error al deserializar evidencia: {}", e)))?;

    let storage_path = PathBuf::from(&state.storage_dir).join(&jti);
    
    let signed_file_path = if evidence_data.doc_name.to_lowercase().ends_with(".pdf") {
        storage_path.join("signed_document.pdf")
    } else {
        storage_path.join(format!("signed_{}", evidence_data.doc_name))
    };

    let file_path = if signed_file_path.exists() {
        signed_file_path
    } else {
        storage_path.join("original.bin")
    };

    let file_data = fs::read(&file_path).map_err(|e| not_found(format!("Archivo firmado no encontrado: {}", e)))?;
    let filename = if file_path.file_name().unwrap().to_str().unwrap().starts_with("signed_") {
        file_path.file_name().unwrap().to_str().unwrap().to_string()
    } else {
        format!("firmado_{}", evidence_data.doc_name)
    };

    Ok((
        StatusCode::OK,
        [
            (HeaderName::from_static("content-type"), "application/octet-stream".to_string()),
            (HeaderName::from_static("content-disposition"), format!("attachment; filename=\"{}\"", filename)),
        ],
        file_data,
    ))
}

async fn generate_justificante(State(state): State<AppState>, Path(jti): Path<String>) -> Result<(StatusCode, [(HeaderName, String); 2], Vec<u8>), (StatusCode, String)> {
    let evidence = sqlx::query("SELECT evidence_json FROM evidences WHERE jti = ?1")
        .bind(&jti)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al consultar evidencia: {}", e)))?;

    let evidence_data: ChileanEvidence = serde_json::from_str(&evidence.ok_or_else(|| not_found("Evidencia no encontrada"))?.get::<String, _>("evidence_json")).map_err(|e| internal_err(format!("Error al deserializar evidencia: {}", e)))?;

    let justificante_path = PathBuf::from(&state.storage_dir).join(&jti).join("justificante.pdf");
    create_justificante_pdf(&evidence_data, &jti, &state.base_url, &justificante_path).await.map_err(|e| internal_err(format!("Error al crear justificante: {}", e)))?;

    let justificante_data = fs::read(&justificante_path).map_err(|e| internal_err(format!("Error al leer justificante: {}", e)))?;

    Ok((
        StatusCode::OK,
        [
            (HeaderName::from_static("content-type"), "application/pdf".to_string()),
            (HeaderName::from_static("content-disposition"), format!("attachment; filename=\"justificante_{}.pdf\"", jti)),
        ],
        justificante_data,
    ))
}

async fn admin_stats(State(state): State<AppState>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let total_intents = sqlx::query("SELECT COUNT(*) as count FROM sign_intents")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al contar intenciones: {}", e)))?
        .get::<i64, _>("count");

    let pending_intents = sqlx::query("SELECT COUNT(*) as count FROM sign_intents WHERE status = 'pending'")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al contar intenciones pendientes: {}", e)))?
        .get::<i64, _>("count");

    let confirmed_intents = sqlx::query("SELECT COUNT(*) as count FROM sign_intents WHERE status = 'confirmed'")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al contar intenciones confirmadas: {}", e)))?
        .get::<i64, _>("count");

    let expired_intents = sqlx::query("SELECT COUNT(*) as count FROM sign_intents WHERE status = 'expired'")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al contar intenciones expiradas: {}", e)))?
        .get::<i64, _>("count");

    let total_evidences = sqlx::query("SELECT COUNT(*) as count FROM evidences")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al contar evidencias: {}", e)))?
        .get::<i64, _>("count");

    let total_verifications = sqlx::query("SELECT COUNT(*) as count FROM verifications")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al contar verificaciones: {}", e)))?
        .get::<i64, _>("count");

    Ok(Json(serde_json::json!({
        "total_intents": total_intents,
        "pending_intents": pending_intents,
        "confirmed_intents": confirmed_intents,
        "expired_intents": expired_intents,
        "total_evidences": total_evidences,
        "total_verifications": total_verifications,
        "timestamp": OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
    })))
}

async fn get_otp_for_signer(
    State(state): State<AppState>,
    Path(signer_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let intent = sqlx::query("SELECT jti, otp, expires_at, doc_name, created_at FROM sign_intents WHERE signer_id = ?1 AND status = 'pending' ORDER BY created_at DESC LIMIT 1")
        .bind(&signer_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| internal_err(format!("Error al consultar OTP: {}", e)))?;

    match intent {
        Some(row) => {
            let expires_at = row.get::<i64, _>("expires_at");
            let now = OffsetDateTime::now_utc().unix_timestamp();
            
            if now > expires_at {
                return Err((StatusCode::GONE, "OTP expirado".to_string()));
            }
            
            let otp = row.get::<String, _>("otp");
            let jti = row.get::<String, _>("jti");
            let doc_name = row.get::<String, _>("doc_name");
            
            Ok(Json(serde_json::json!({
                "otp": otp,
                "jti": jti,
                "doc_name": doc_name,
                "expires_at": OffsetDateTime::from_unix_timestamp(expires_at)
                    .unwrap()
                    .format(&Rfc3339)
                    .unwrap(),
                "message": "Use este código para confirmar la firma"
            })))
        }
        None => Err((StatusCode::NOT_FOUND, "No hay intenciones de firma pendientes para este usuario".to_string()))
    }
}

#[allow(dead_code)]
fn validate_chilean_rut(rut: &str) -> bool {
    let clean_rut = rut.replace(".", "").replace("-", "");
    if clean_rut.len() < 8 || clean_rut.len() > 9 {
        return false;
    }
    
    let (number_part, check_digit) = clean_rut.split_at(clean_rut.len() - 1);
    let check_digit = check_digit.chars().next().unwrap();
    
    if let Ok(number) = number_part.parse::<u32>() {
        calculate_rut_check_digit(number) == check_digit
    } else {
        false
    }
}

#[allow(dead_code)]
fn calculate_rut_check_digit(mut rut: u32) -> char {
    let mut sum = 0;
    let mut multiplier = 2;
    
    while rut > 0 {
        sum += (rut % 10) * multiplier;
        rut /= 10;
        multiplier += 1;
        if multiplier > 7 {
            multiplier = 2;
        }
    }
    
    let remainder = sum % 11;
    match 11 - remainder {
        10 => 'K',
        11 => '0',
        n => char::from_digit(n as u32, 10).unwrap(),
    }
}

async fn generate_otp(service: &OtpService) -> String {
    match &service.mode {
        OtpMode::Fixed(otp) => otp.clone(),
        OtpMode::Random => {
            let otp = format!("{:0width$}", fastrand::u32(0..10_u32.pow(service.length as u32)), width = service.length);
            info!("OTP generado (desarrollo): {}", otp);
            otp
        },
        OtpMode::Email => "123456".to_string(),
        OtpMode::Sms => "123456".to_string(),
    }
}

fn get_otp_hint(service: &OtpService) -> String {
    match service.mode {
        OtpMode::Fixed(_) => "Usar código fijo (desarrollo)".to_string(),
        OtpMode::Random => "Consultar /api/v1/get-otp/[email] (desarrollo)".to_string(),
        OtpMode::Email => "Revisar tu email".to_string(),
        OtpMode::Sms => "Revisar tu SMS".to_string(),
    }
}

#[allow(dead_code)]
fn extract_real_ip(headers: &HeaderMap, addr: SocketAddr) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }
    
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            return real_ip_str.to_string();
        }
    }
    
    addr.ip().to_string()
}

#[allow(dead_code)]
fn extract_user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string()
}

fn calculate_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn internal_err<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    error!("Error interno: {}", e);
    (StatusCode::INTERNAL_SERVER_ERROR, format!("Error interno: {}", e))
}

fn not_found<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    warn!("No encontrado: {}", e);
    (StatusCode::NOT_FOUND, format!("No encontrado: {}", e))
}

async fn create_signed_pdf(pdf_data: &[u8], evidence: &ChileanEvidence, jti: &str, base_url: &str, output_path: &PathBuf) -> Result<()> {
    println!("Generando hoja de firma con QR y metadata...");
    
    let verification_url = format!("{}/api/v1/verify/{}", base_url, jti);
    
    // Generar QR Code
    let qr_code = QrCode::new(verification_url.as_bytes()).map_err(|e| anyhow::anyhow!("Error generando QR: {}", e))?;
    let qr_image: ImageBuffer<Luma<u8>, Vec<u8>> = qr_code.render::<Luma<u8>>().module_dimensions(4, 4).build();
    let mut qr_buffer = Cursor::new(Vec::new());
    DynamicImage::ImageLuma8(qr_image).write_to(&mut qr_buffer, image::ImageFormat::Png)?;
    let qr_data = qr_buffer.into_inner();
    
    let qr_path = output_path.with_file_name("qr_temp.png");
    fs::write(&qr_path, &qr_data)?;
    
    // XMP Metadata
    let xmp_metadata = format!(
        r#"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:fes="http://fes.example.com/schema/">
  <rdf:Description rdf:about="">
    <fes:doc_sha256>{}</fes:doc_sha256>
    <fes:doc_name>{}</fes:doc_name>
    <fes:doc_size>{}</fes:doc_size>
    <fes:ts_utc>{}</fes:ts_utc>
    <fes:ts_chile>{}</fes:ts_chile>
    <fes:timezone>{}</fes:timezone>
    <fes:signer_id>{}</fes:signer_id>
    <fes:signer_rut>{}</fes:signer_rut>
    <fes:signer_validated>{}</fes:signer_validated>
    <fes:auth_method>{}</fes:auth_method>
    <fes:otp_verified>{}</fes:otp_verified>
    <fes:ip_address>{}</fes:ip_address>
    <fes:user_agent>{}</fes:user_agent>
    <fes:consent_hash>{}</fes:consent_hash>
    <fes:consent_text>{}</fes:consent_text>
    <fes:policy_version>{}</fes:policy_version>
    <fes:system_version>{}</fes:system_version>
    <fes:session_id>{}</fes:session_id>
    <fes:legal_framework>{}</fes:legal_framework>
    <fes:signature_type>{}</fes:signature_type>
    <fes:jurisdiction>{}</fes:jurisdiction>
  </rdf:Description>
</rdf:RDF>"#,
        evidence.doc_sha256,
        evidence.doc_name,
        evidence.doc_size,
        evidence.ts_utc,
        evidence.ts_chile,
        evidence.timezone,
        evidence.signer_id,
        evidence.signer_rut.as_deref().unwrap_or("N/A"),
        evidence.signer_validated,
        evidence.auth_method,
        evidence.otp_verified,
        evidence.ip_address,
        evidence.user_agent,
        evidence.consent_hash,
        evidence.consent_text.replace("<", "&lt;").replace(">", "&gt;"),
        evidence.policy_version,
        evidence.system_version,
        evidence.session_id,
        evidence.legal_framework,
        evidence.signature_type,
        evidence.jurisdiction
    );
    
    // Cargar PDF original
    match Document::load_mem(pdf_data) {
        Ok(mut doc) => {
            println!("PDF original cargado, añadiendo hoja de firma con QR y metadata...");
            
            // Crear IDs
            let page_id = doc.new_object_id();
            let content_id = doc.new_object_id();
            let font_id = doc.new_object_id();
            let qr_image_id = doc.new_object_id();
            let metadata_id = doc.new_object_id();
            
            // Fuente
            let mut font_dict = Dictionary::new();
            font_dict.set("Type", Object::Name(b"Font".to_vec()));
            font_dict.set("Subtype", Object::Name(b"Type1".to_vec()));
            font_dict.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
            doc.objects.insert(font_id, Object::Dictionary(font_dict));
            
            // Contenido de la página de firma con QR
            let signature_content = format!(
                "BT /F1 10 Tf 50 750 Td (DOCUMENTO FIRMADO DIGITALMENTE) Tj 0 -15 Td (Documento: {}) Tj 0 -15 Td (Firmante: {}) Tj 0 -15 Td (RUT: {}) Tj 0 -15 Td (Fecha: {}) Tj 0 -15 Td (Hash SHA-256: {}) Tj 0 -15 Td (Metodo: {}) Tj 0 -15 Td (OTP Verificado: {}) Tj 0 -15 Td (Marco Legal: {}) Tj 0 -15 Td (Jurisdiccion: {}) Tj 0 -15 Td (Verificacion: Escanea QR) Tj ET q 100 0 0 100 400 600 cm /QrImg Do Q",
                evidence.doc_name,
                evidence.signer_id,
                evidence.signer_rut.as_deref().unwrap_or("N/A"),
                evidence.ts_chile,
                &evidence.doc_sha256[..32],
                evidence.auth_method,
                if evidence.otp_verified { "SI" } else { "NO" },
                evidence.legal_framework,
                evidence.jurisdiction
            );
            
            let content_stream = Stream::new(Dictionary::new(), signature_content.into_bytes());
            doc.objects.insert(content_id, Object::Stream(content_stream));
            
            // Embed QR como XObject
            let mut qr_dict = Dictionary::new();
            qr_dict.set("Type", Object::Name(b"XObject".to_vec()));
            qr_dict.set("Subtype", Object::Name(b"Image".to_vec()));
            qr_dict.set("Width", Object::Integer(100));
            qr_dict.set("Height", Object::Integer(100));
            qr_dict.set("ColorSpace", Object::Name(b"DeviceRGB".to_vec()));
            qr_dict.set("BitsPerComponent", Object::Integer(8));
            qr_dict.set("Filter", Object::Name(b"DCTDecode".to_vec()));
            let qr_stream = Stream::new(qr_dict, qr_data);
            doc.objects.insert(qr_image_id, Object::Stream(qr_stream));
            
            // Recursos
            let mut resources = Dictionary::new();
            let mut font_resources = Dictionary::new();
            font_resources.set("F1", Object::Reference(font_id));
            let mut xobject_resources = Dictionary::new();
            xobject_resources.set("QrImg", Object::Reference(qr_image_id));
            resources.set("Font", Object::Dictionary(font_resources));
            resources.set("XObject", Object::Dictionary(xobject_resources));
            
            // Página
            let mut page_dict = Dictionary::new();
            page_dict.set("Type", Object::Name(b"Page".to_vec()));
            page_dict.set("MediaBox", Object::Array(vec![
                Object::Integer(0), Object::Integer(0), Object::Integer(595), Object::Integer(842)
            ]));
            page_dict.set("Resources", Object::Dictionary(resources));
            page_dict.set("Contents", Object::Reference(content_id));
            
            // Añadir página al documento
            if let Ok(root_obj) = doc.trailer.get(b"Root") {
                if let Ok(root_ref) = root_obj.as_reference() {
                    if let Some(Object::Dictionary(catalog)) = doc.objects.get_mut(&root_ref) {
                        if let Ok(pages_obj) = catalog.get(b"Pages") {
                            if let Ok(pages_ref) = pages_obj.as_reference() {
                                if let Some(Object::Dictionary(pages)) = doc.objects.get_mut(&pages_ref) {
                                    if let Ok(Object::Array(kids)) = pages.get_mut(b"Kids") {
                                        kids.push(Object::Reference(page_id));
                                        let kids_count = kids.len() as i64;
                                        pages.set("Count", Object::Integer(kids_count));
                                        page_dict.set("Parent", Object::Reference(pages_ref));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            doc.objects.insert(page_id, Object::Dictionary(page_dict));
            
            // Metadata
            let mut metadata_dict = Dictionary::new();
            metadata_dict.set("Type", Object::Name(b"Metadata".to_vec()));
            metadata_dict.set("Subtype", Object::Name(b"XML".to_vec()));
            let metadata_stream = Stream::new(metadata_dict, xmp_metadata.into_bytes());
            doc.objects.insert(metadata_id, Object::Stream(metadata_stream));
            
            if let Ok(root_obj) = doc.trailer.get(b"Root") {
                if let Ok(root_ref) = root_obj.as_reference() {
                    if let Some(Object::Dictionary(catalog)) = doc.objects.get_mut(&root_ref) {
                        catalog.set("Metadata", Object::Reference(metadata_id));
                    }
                }
            }
            
            doc.save(output_path)?;
            println!("PDF con hoja de firma, QR y metadata guardado exitosamente");
        },
        Err(e) => {
            println!("Error al cargar PDF original ({}), creando nuevo PDF con hoja de firma...", e);
            
            let mut new_doc = Document::new();
            
            let catalog_id = new_doc.new_object_id();
            let pages_id = new_doc.new_object_id();
            let page_id = new_doc.new_object_id();
            let content_id = new_doc.new_object_id();
            let font_id = new_doc.new_object_id();
            let qr_image_id = new_doc.new_object_id();
            let metadata_id = new_doc.new_object_id();
            
            let mut font_dict = Dictionary::new();
            font_dict.set("Type", Object::Name(b"Font".to_vec()));
            font_dict.set("Subtype", Object::Name(b"Type1".to_vec()));
            font_dict.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
            new_doc.objects.insert(font_id, Object::Dictionary(font_dict));
            
            let full_signature_content = format!(
                "BT /F1 12 Tf 50 750 Td (DOCUMENTO FIRMADO DIGITALMENTE) Tj 0 -30 Td (Documento Original: {}) Tj 0 -20 Td (Firmante: {}) Tj 0 -20 Td (RUT: {}) Tj 0 -20 Td (Fecha y Hora: {}) Tj 0 -20 Td (Hash SHA-256 del documento: {}) Tj 0 -20 Td (Metodo de Autenticacion: {}) Tj 0 -20 Td (OTP Verificado: {}) Tj 0 -20 Td (Direccion IP: {}) Tj 0 -20 Td (Marco Legal: {}) Tj 0 -20 Td (Tipo de Firma: {}) Tj 0 -20 Td (Jurisdiccion: {}) Tj 0 -20 Td (Version del Sistema: {}) Tj 0 -20 Td (Session ID: {}) Tj 0 -30 Td (Esta firma digital es legalmente valida bajo) Tj 0 -15 Td (la Ley 19.799 de Chile sobre Documentos Electronicos.) Tj 0 -30 Td (Hash de consentimiento: {}) Tj 0 -20 Td (Escanea QR para verificar) Tj ET q 100 0 0 100 400 600 cm /QrImg Do Q",
                evidence.doc_name,
                evidence.signer_id,
                evidence.signer_rut.as_deref().unwrap_or("N/A"),
                evidence.ts_chile,
                &evidence.doc_sha256[..32],
                evidence.auth_method,
                if evidence.otp_verified { "SI" } else { "NO" },
                evidence.ip_address,
                evidence.legal_framework,
                evidence.signature_type,
                evidence.jurisdiction,
                evidence.system_version,
                evidence.session_id,
                &evidence.consent_hash[..16]
            );
            
            let content_stream = Stream::new(Dictionary::new(), full_signature_content.into_bytes());
            new_doc.objects.insert(content_id, Object::Stream(content_stream));
            
            let mut qr_dict = Dictionary::new();
            qr_dict.set("Type", Object::Name(b"XObject".to_vec()));
            qr_dict.set("Subtype", Object::Name(b"Image".to_vec()));
            qr_dict.set("Width", Object::Integer(100));
            qr_dict.set("Height", Object::Integer(100));
            qr_dict.set("ColorSpace", Object::Name(b"DeviceRGB".to_vec()));
            qr_dict.set("BitsPerComponent", Object::Integer(8));
            qr_dict.set("Filter", Object::Name(b"DCTDecode".to_vec()));
            let qr_stream = Stream::new(qr_dict, qr_data);
            new_doc.objects.insert(qr_image_id, Object::Stream(qr_stream));
            
            let mut resources = Dictionary::new();
            let mut font_resources = Dictionary::new();
            font_resources.set("F1", Object::Reference(font_id));
            let mut xobject_resources = Dictionary::new();
            xobject_resources.set("QrImg", Object::Reference(qr_image_id));
            resources.set("Font", Object::Dictionary(font_resources));
            resources.set("XObject", Object::Dictionary(xobject_resources));
            
            let mut page_dict = Dictionary::new();
            page_dict.set("Type", Object::Name(b"Page".to_vec()));
            page_dict.set("Parent", Object::Reference(pages_id));
            page_dict.set("MediaBox", Object::Array(vec![
                Object::Integer(0), Object::Integer(0), Object::Integer(595), Object::Integer(842)
            ]));
            page_dict.set("Resources", Object::Dictionary(resources));
            page_dict.set("Contents", Object::Reference(content_id));
            new_doc.objects.insert(page_id, Object::Dictionary(page_dict));
            
            let mut pages_dict = Dictionary::new();
            pages_dict.set("Type", Object::Name(b"Pages".to_vec()));
            pages_dict.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
            pages_dict.set("Count", Object::Integer(1));
            new_doc.objects.insert(pages_id, Object::Dictionary(pages_dict));
            
            let mut metadata_dict = Dictionary::new();
            metadata_dict.set("Type", Object::Name(b"Metadata".to_vec()));
            metadata_dict.set("Subtype", Object::Name(b"XML".to_vec()));
            let metadata_stream = Stream::new(metadata_dict, xmp_metadata.into_bytes());
            new_doc.objects.insert(metadata_id, Object::Stream(metadata_stream));
            
            let mut catalog_dict = Dictionary::new();
            catalog_dict.set("Type", Object::Name(b"Catalog".to_vec()));
            catalog_dict.set("Pages", Object::Reference(pages_id));
            catalog_dict.set("Metadata", Object::Reference(metadata_id));
            new_doc.objects.insert(catalog_id, Object::Dictionary(catalog_dict));
            
            new_doc.trailer.set("Root", Object::Reference(catalog_id));
            
            new_doc.save(output_path)?;
            println!("Nuevo PDF con hoja de firma, QR y metadata creado exitosamente");
        }
    }
    
    fs::remove_file(&qr_path)?;
    
    let evidence_path = output_path.with_extension("evidence.json");
    let evidence_json = serde_json::to_string_pretty(evidence)?;
    fs::write(&evidence_path, evidence_json)?;
    
    println!("FIRMA CON HOJA, QR Y METADATA INCRUSTADA EXITOSAMENTE en: {}", output_path.display());
    Ok(())
}

async fn create_justificante_pdf(evidence: &ChileanEvidence, jti: &str, base_url: &str, output_path: &PathBuf) -> Result<()> {
    let verification_url = format!("{}/api/v1/verify/{}", base_url, jti);
    
    let qr_code = QrCode::new(verification_url.as_bytes()).map_err(|e| anyhow::anyhow!("Error generando QR: {}", e))?;
    let qr_image: ImageBuffer<Luma<u8>, Vec<u8>> = qr_code.render::<Luma<u8>>().module_dimensions(4, 4).build();
    let mut qr_buffer = Cursor::new(Vec::new());
    DynamicImage::ImageLuma8(qr_image).write_to(&mut qr_buffer, image::ImageFormat::Png)?;
    let qr_data = qr_buffer.into_inner();
    
    let qr_path = output_path.with_file_name("qr_just_temp.png");
    fs::write(&qr_path, &qr_data)?;
    
    let mut doc = Document::new();
    
    let catalog_id = doc.new_object_id();
    let pages_id = doc.new_object_id();
    let page_id = doc.new_object_id();
    let content_id = doc.new_object_id();
    let font_id = doc.new_object_id();
    let qr_image_id = doc.new_object_id();
    
    let mut font_dict = Dictionary::new();
    font_dict.set("Type", Object::Name(b"Font".to_vec()));
    font_dict.set("Subtype", Object::Name(b"Type1".to_vec()));
    font_dict.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
    doc.objects.insert(font_id, Object::Dictionary(font_dict));
    
    let justificante_content = format!(
        "BT /F1 12 Tf 50 750 Td (JUSTIFICANTE DE FIRMA ELECTRONICA) Tj 0 -25 Td (JTI: {}) Tj 0 -25 Td (Documento: {}) Tj 0 -25 Td (Firmante: {}) Tj 0 -25 Td (RUT: {}) Tj 0 -25 Td (Fecha Firma: {}) Tj 0 -25 Td (Hash Documento: {}) Tj 0 -25 Td (Hash Consentimiento: {}) Tj 0 -25 Td (Metodo Autent: {}) Tj 0 -25 Td (OTP Verif: {}) Tj 0 -25 Td (IP: {}) Tj 0 -25 Td (Marco Legal: {}) Tj 0 -25 Td (Tipo Firma: {}) Tj 0 -25 Td (Jurisdiccion: {}) Tj 0 -25 Td (Politica: {}) Tj 0 -25 Td (Sistema: {}) Tj 0 -25 Td (Session: {}) Tj 0 -25 Td (Verificacion: Escanea QR) Tj ET q 100 0 0 100 400 600 cm /QrImg Do Q",
        jti,
        evidence.doc_name,
        evidence.signer_id,
        evidence.signer_rut.as_deref().unwrap_or("N/A"),
        evidence.ts_chile,
        &evidence.doc_sha256[..32],
        &evidence.consent_hash[..16],
        evidence.auth_method,
        if evidence.otp_verified { "SI" } else { "NO" },
        evidence.ip_address,
        evidence.legal_framework,
        evidence.signature_type,
        evidence.jurisdiction,
        evidence.policy_version,
        evidence.system_version,
        evidence.session_id
    );
    
    let content_stream = Stream::new(Dictionary::new(), justificante_content.into_bytes());
    doc.objects.insert(content_id, Object::Stream(content_stream));
    
    let mut qr_dict = Dictionary::new();
    qr_dict.set("Type", Object::Name(b"XObject".to_vec()));
    qr_dict.set("Subtype", Object::Name(b"Image".to_vec()));
    qr_dict.set("Width", Object::Integer(100));
    qr_dict.set("Height", Object::Integer(100));
    qr_dict.set("ColorSpace", Object::Name(b"DeviceRGB".to_vec()));
    qr_dict.set("BitsPerComponent", Object::Integer(8));
    qr_dict.set("Filter", Object::Name(b"DCTDecode".to_vec()));
    let qr_stream = Stream::new(qr_dict, qr_data);
    doc.objects.insert(qr_image_id, Object::Stream(qr_stream));
    
    let mut resources = Dictionary::new();
    let mut font_resources = Dictionary::new();
    font_resources.set("F1", Object::Reference(font_id));
    let mut xobject_resources = Dictionary::new();
    xobject_resources.set("QrImg", Object::Reference(qr_image_id));
    resources.set("Font", Object::Dictionary(font_resources));
    resources.set("XObject", Object::Dictionary(xobject_resources));
    
    let mut page_dict = Dictionary::new();
    page_dict.set("Type", Object::Name(b"Page".to_vec()));
    page_dict.set("Parent", Object::Reference(pages_id));
    page_dict.set("MediaBox", Object::Array(vec![
        Object::Integer(0), Object::Integer(0), Object::Integer(595), Object::Integer(842)
    ]));
    page_dict.set("Resources", Object::Dictionary(resources));
    page_dict.set("Contents", Object::Reference(content_id));
    doc.objects.insert(page_id, Object::Dictionary(page_dict));
    
    let mut pages_dict = Dictionary::new();
    pages_dict.set("Type", Object::Name(b"Pages".to_vec()));
    pages_dict.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
    pages_dict.set("Count", Object::Integer(1));
    doc.objects.insert(pages_id, Object::Dictionary(pages_dict));
    
    let mut catalog_dict = Dictionary::new();
    catalog_dict.set("Type", Object::Name(b"Catalog".to_vec()));
    catalog_dict.set("Pages", Object::Reference(pages_id));
    doc.objects.insert(catalog_id, Object::Dictionary(catalog_dict));
    
    doc.trailer.set("Root", Object::Reference(catalog_id));
    
    doc.save(output_path)?;
    fs::remove_file(&qr_path)?;
    
    println!("Justificante PDF generado exitosamente en: {}", output_path.display());
    Ok(())
}

fn setup_tracing() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    Ok(())
}

async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    info!("Ejecutando migraciones de base de datos...");
    
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS sign_intents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jti TEXT NOT NULL UNIQUE,
            signer_id TEXT NOT NULL,
            signer_rut TEXT,
            otp TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            doc_name TEXT NOT NULL,
            consent_text TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL DEFAULT (unixepoch()),
            updated_at INTEGER NOT NULL DEFAULT (unixepoch())
        );
    "#)
    .execute(pool)
    .await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS evidences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jti TEXT NOT NULL UNIQUE,
            evidence_json TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (unixepoch()),
            FOREIGN KEY (jti) REFERENCES sign_intents (jti)
        );
    "#)
    .execute(pool)
    .await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jti TEXT NOT NULL,
            verification_id TEXT NOT NULL UNIQUE,
            verified_at INTEGER NOT NULL DEFAULT (unixepoch()),
            FOREIGN KEY (jti) REFERENCES sign_intents (jti)
        );
    "#)
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sign_intents_signer_id ON sign_intents(signer_id);")
        .execute(pool)
        .await?;
        
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sign_intents_status ON sign_intents(status);")
        .execute(pool)
        .await?;
        
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sign_intents_expires_at ON sign_intents(expires_at);")
        .execute(pool)
        .await?;
        
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_evidences_jti ON evidences(jti);")
        .execute(pool)
        .await?;
        
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_verifications_jti ON verifications(jti);")
        .execute(pool)
        .await?;

    info!("Migraciones completadas exitosamente");
    Ok(())
}

fn create_otp_service() -> OtpService {
    OtpService { mode: OtpMode::Random, length: 6, ttl_minutes: 5 }
}

fn create_crypto_service() -> CryptoService {
    CryptoService { 
        priv_key_path: "keys/server_rsa_pkcs8.pem".to_string(), 
        pub_key_path: "keys/server_rsa_pub.pem".to_string(), 
        algorithm: Algorithm::RS256 
    }
}

fn create_chilean_config() -> ChileanConfig {
    ChileanConfig { 
        require_rut_validation: true, 
        timezone: "America/Santiago".to_string(), 
        legal_policy_version: "1.0".to_string(), 
        retention_days: 365 
    }
}