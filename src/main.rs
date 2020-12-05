use actix_web::{http, middleware, web, App, HttpRequest, HttpResponse, HttpServer, ResponseError};
use futures::StreamExt;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use tokio::fs::os::unix::OpenOptionsExt;
use tokio::io::AsyncWriteExt;

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Actix(#[from] actix_web::Error),
    #[error(transparent)]
    ActixPayload(#[from] actix_web::error::PayloadError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    #[error("invalid file type")]
    InvalidFileType,
    #[error("file name is too short")]
    FilenameIsTooShort,
    #[error("path is not valid UTF-8")]
    PathIsNotValidUtf8,
    #[error("type parameter missing")]
    TypeParamMissing,
    #[error("name parameter missing")]
    NameParamMissing,
    #[error("no parent directory")]
    NoParentDir,
}

impl ResponseError for Error {
    fn status_code(&self) -> http::StatusCode {
        log::error!("ResponseError: {}", self);

        match self {
            Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound => http::StatusCode::NOT_FOUND,
            Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                http::StatusCode::FORBIDDEN
            }
            Error::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                http::StatusCode::FORBIDDEN
            }
            _ => http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Clone)]
struct Server {
    path: String,
}

static VALID_TYPES: &[&str] = &["data", "index", "keys", "locks", "snapshots", "config"];

static MIMETYPE_API_V1: &str = "application/vnd.x.restic.rest.v1";
static MIMETYPE_API_V2: &str = "application/vnd.x.restic.rest.v2";

fn is_valid_type(t1: &str) -> bool {
    for &t2 in VALID_TYPES {
        if t1 == t2 {
            return true;
        }
    }

    false
}

fn is_hashed(dir: &str) -> bool {
    dir == "data"
}

fn get_repo(req: &HttpRequest) -> &str {
    req.match_info().get("repo").unwrap_or(".")
}

async fn open_file_write(
    path: impl AsRef<std::path::Path>,
) -> Result<tokio::fs::File, std::io::Error> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await
}

impl Server {
    pub async fn get_path<P: AsRef<std::path::Path>>(
        &self,
        req: &HttpRequest,
        filetype: P,
    ) -> Result<std::path::PathBuf, Error> {
        if !is_valid_type(
            filetype
                .as_ref()
                .to_str()
                .ok_or(Error::PathIsNotValidUtf8)?,
        ) {
            return Err(Error::InvalidFileType);
        }

        Ok(std::path::Path::new(&self.path)
            .join(get_repo(req))
            .join(filetype))
    }

    pub async fn get_file_path(
        &self,
        req: &HttpRequest,
        filetype: &str,
        name: &str,
    ) -> Result<std::path::PathBuf, Error> {
        if !is_valid_type(filetype) {
            return Err(Error::InvalidFileType);
        }

        if is_hashed(filetype) {
            if filetype.len() < 2 {
                return Err(Error::FilenameIsTooShort);
            }

            return Ok(std::path::Path::new(&self.path)
                .join(get_repo(req))
                .join(filetype)
                .join(&name[..2])
                .join(name));
        }

        Ok(std::path::Path::new(&self.path)
            .join(get_repo(req))
            .join(filetype)
            .join(name))
    }

    pub async fn get_file_path_from_req(
        &self,
        req: &HttpRequest,
    ) -> Result<std::path::PathBuf, Error> {
        let filetype = req
            .match_info()
            .get("type")
            .ok_or(Error::TypeParamMissing)?;
        let filename = req
            .match_info()
            .get("name")
            .ok_or(Error::NameParamMissing)?;
        self.get_file_path(&req, &filetype, &filename).await
    }
}

async fn get_config(req: HttpRequest, srv: web::Data<Server>) -> Result<HttpResponse, Error> {
    let cfg = srv.get_path(&req, "config").await?;
    Ok(actix_files::NamedFile::open(cfg)?.into_response(&req)?)
}

async fn save_config(
    req: HttpRequest,
    mut body: web::Payload,
    srv: web::Data<Server>,
) -> Result<HttpResponse, Error> {
    let cfg = srv.get_path(&req, "config").await?;

    let mut file = open_file_write(&cfg).await?;

    while let Some(chunk) = body.next().await {
        file.write_all(&chunk?).await?;
    }

    Ok(HttpResponse::Ok().finish())
}

async fn delete_config(req: HttpRequest, srv: web::Data<Server>) -> Result<HttpResponse, Error> {
    let cfg = srv.get_path(&req, "config").await?;

    tokio::fs::remove_file(&cfg).await?;

    Ok(HttpResponse::Ok().finish())
}

async fn list_blobs_v1(req: HttpRequest, srv: web::Data<Server>) -> Result<HttpResponse, Error> {
    let filetype = req
        .match_info()
        .get("type")
        .ok_or(Error::TypeParamMissing)?;
    let path = srv.get_path(&req, &filetype).await?;

    let mut names = Vec::new();
    let mut items = tokio::fs::read_dir(&path).await?;
    while let Some(entry) = items.next_entry().await? {
        if is_hashed(filetype) {
            let subpath = entry.path();
            let mut subitems = tokio::fs::read_dir(&subpath).await?;
            while let Some(entry) = subitems.next_entry().await? {
                names.push(
                    entry
                        .file_name()
                        .to_str()
                        .ok_or(Error::PathIsNotValidUtf8)?
                        .to_string(),
                );
            }
        } else {
            names.push(
                entry
                    .file_name()
                    .to_str()
                    .ok_or(Error::PathIsNotValidUtf8)?
                    .to_string(),
            );
        }
    }

    Ok(HttpResponse::Ok()
        .content_type(MIMETYPE_API_V1)
        .body(serde_json::to_string(&names)?))
}

#[derive(serde::Serialize)]
struct Blob {
    name: String,
    size: u64,
}

impl Blob {
    pub async fn new(entry: &tokio::fs::DirEntry) -> Result<Self, Error> {
        Ok(Self {
            name: entry
                .file_name()
                .to_str()
                .ok_or(Error::PathIsNotValidUtf8)?
                .to_string(),
            size: entry.metadata().await?.len(),
        })
    }
}

async fn list_blobs_v2(req: HttpRequest, srv: web::Data<Server>) -> Result<HttpResponse, Error> {
    let filetype = req
        .match_info()
        .get("type")
        .ok_or(Error::TypeParamMissing)?;
    let path = srv.get_path(&req, &filetype).await?;

    let mut blobs = Vec::new();
    let mut items = tokio::fs::read_dir(&path).await?;
    while let Some(entry) = items.next_entry().await? {
        if is_hashed(filetype) {
            let subpath = entry.path();
            let mut subitems = tokio::fs::read_dir(&subpath).await?;
            while let Some(entry) = subitems.next_entry().await? {
                blobs.push(Blob::new(&entry).await?);
            }
        } else {
            blobs.push(Blob::new(&entry).await?);
        }
    }

    Ok(HttpResponse::Ok()
        .content_type(MIMETYPE_API_V2)
        .body(serde_json::to_string(&blobs)?))
}

async fn list_blobs(req: HttpRequest, srv: web::Data<Server>) -> Result<HttpResponse, Error> {
    match req.headers().get("Accept") {
        Some(v) if v == MIMETYPE_API_V2 => list_blobs_v2(req, srv).await,
        _ => list_blobs_v1(req, srv).await,
    }
}

async fn get_blob(req: HttpRequest, srv: web::Data<Server>) -> Result<HttpResponse, Error> {
    let path = srv.get_file_path_from_req(&req).await?;
    Ok(actix_files::NamedFile::open(&path)?.into_response(&req)?)
}

async fn save_blob_internal(
    mut file: tokio::fs::File,
    body: &mut web::Payload,
) -> Result<(), Error> {
    while let Some(chunk) = body.next().await {
        file.write_all(&chunk?).await?;
    }

    file.sync_all().await?;

    Ok(())
}

async fn save_blob(
    req: HttpRequest,
    mut body: web::Payload,
    srv: web::Data<Server>,
) -> Result<HttpResponse, Error> {
    let path = srv.get_file_path_from_req(&req).await?;

    let file = match open_file_write(&path).await {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // the error is caused by a missing directory, create it and retry
            tokio::fs::create_dir_all(path.parent().ok_or(Error::NoParentDir)?).await?;
            open_file_write(&path).await
        }
        Err(e) => Err(e),
    }?;

    match save_blob_internal(file, &mut body).await {
        Ok(_) => (),
        Err(e) => {
            tokio::fs::remove_file(&path).await?;
            return Err(e);
        }
    }

    Ok(HttpResponse::Ok().finish())
}

async fn delete_blob(req: HttpRequest, srv: web::Data<Server>) -> Result<HttpResponse, Error> {
    let path = srv.get_file_path_from_req(&req).await?;

    tokio::fs::remove_file(&path).await?;

    Ok(HttpResponse::Ok().finish())
}

async fn create_repo(_req: HttpRequest, _srv: web::Data<Server>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::NotImplemented().finish())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let matches = clap::App::new(clap::crate_name!())
        .arg(
            clap::Arg::with_name("listen")
                .long("listen")
                .help("listen address")
                .takes_value(true)
                .default_value("0.0.0.0:8000"),
        )
        .arg(
            clap::Arg::with_name("path")
                .long("path")
                .help("data directory")
                .takes_value(true)
                .default_value("/tmp/restic"),
        )
        .arg(
            clap::Arg::with_name("tls-ca")
                .long("tls-ca")
                .help("TLS trusted root certificates file")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("tls-cert")
                .long("tls-cert")
                .help("TLS certificate path")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("tls-key")
                .long("tls-key")
                .help("TLS key path")
                .takes_value(true),
        )
        .get_matches();
    let addr = matches.value_of("listen").unwrap();
    let path = matches.value_of("path").unwrap();
    let tls_ca = matches.value_of("tls-ca");
    let tls_cert = matches
        .value_of("tls-cert")
        .expect("option 'tls-cert' missing");
    let tls_key = matches
        .value_of("tls-key")
        .expect("option 'tls-key' missing");
    let server = Server {
        path: path.to_string(),
    };

    env_logger::init();

    // load ssl keys
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(tls_key, SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file(tls_cert).unwrap();

    if let Some(tls_ca) = tls_ca {
        builder.set_ca_file(tls_ca).unwrap();

        let mut verify_mode = SslVerifyMode::empty();
        verify_mode.set(SslVerifyMode::PEER, true);
        verify_mode.set(SslVerifyMode::FAIL_IF_NO_PEER_CERT, true);
        builder.set_verify(verify_mode);
    }

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .wrap(middleware::Logger::default())
            // config
            .route("/config", web::head().to(get_config))
            .route("/{repo}/config", web::head().to(get_config))
            .route("/config", web::get().to(get_config))
            .route("/{repo}/config", web::get().to(get_config))
            .route("/config", web::post().to(save_config))
            .route("/{repo}/config", web::post().to(save_config))
            .route("/config", web::delete().to(delete_config))
            .route("/{repo}/config", web::delete().to(delete_config))
            // blobs
            .route("/{type}/", web::get().to(list_blobs))
            .route("/{repo}/{type}/", web::get().to(list_blobs))
            .route("/{type}/{name}", web::head().to(get_blob))
            .route("/{repo}/{type}/{name}", web::head().to(get_blob))
            .route("/{type}/{name}", web::get().to(get_blob))
            .route("/{repo}/{type}/{name}", web::get().to(get_blob))
            .route("/{type}/{name}", web::post().to(save_blob))
            .route("/{repo}/{type}/{name}", web::post().to(save_blob))
            .route("/{type}/{name}", web::delete().to(delete_blob))
            .route("/{repo}/{type}/{name}", web::delete().to(delete_blob))
            // create
            .route("/", web::post().to(create_repo))
            .route("/{repo}", web::post().to(create_repo))
            .route("/{repo}/", web::post().to(create_repo))
    })
    .bind_openssl(addr, builder)?
    .run()
    .await
}
