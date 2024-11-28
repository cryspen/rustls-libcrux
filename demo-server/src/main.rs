use std::{any::Any, sync::Arc};

use actix_web::{dev::Extensions, middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig, DEFAULT_VERSIONS,
};

mod index;

static BULMA_CSS: &str = include_str!("../assets/bulma.min.css");

type TlsSession = actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>;

async fn bulma_min_css(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().content_type("text/css").body(BULMA_CSS)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if let Err(err) = real_main().await {
        println!("error: {err}");
        std::process::exit(1);
    }

    Ok(())
}

async fn real_main() -> Result<(), Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let config = load_rustls_config()?;

    log::info!("starting HTTPS server at https://localhost:8443");

    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            // register simple handler, handle all methods
            .service(web::resource("/index.html").to(index::handle))
            .service(web::resource("/bulma.min.css").to(bulma_min_css))
            .service(web::redirect("/", "/index.html"))
    })
    .on_connect(extract_kx_group)
    .bind_rustls_0_23("127.0.0.1:8443", config)
    .map_err(Error::RustlsBind)?
    .run()
    .await
    .map_err(Error::RustlsRun)
}

/// Extracts the named group used to connect and stored it in the extensions of the _connection_
/// (not the request!)
fn extract_kx_group(session: &dyn Any, extensions: &mut Extensions) {
    let (_, conn) = session.downcast_ref::<TlsSession>().unwrap().get_ref();
    let group = conn.negotiated_key_exchange_group().unwrap();
    extensions.insert(group.name());
}

fn load_rustls_config() -> Result<ServerConfig, Error> {
    let args: Vec<String> = std::env::args().collect();
    let args: [String; 3] = args
        .try_into()
        .map_err(|args: Vec<_>| Error::WrongArgumentCount(args.len()))?;

    let [_, cert_file, private_key_file] = args;

    let certs: Result<Vec<_>, _> = CertificateDer::pem_file_iter(cert_file)
        .map_err(Error::LoadCertFile)?
        .collect();
    let certs = certs.map_err(Error::LoadCertFile)?;

    let private_key = PrivateKeyDer::from_pem_file(private_key_file).map_err(Error::LoadKeyFile)?;

    ServerConfig::builder_with_provider(Arc::new(rustls_libcrux_provider::provider()))
        .with_protocol_versions(DEFAULT_VERSIONS)
        .map_err(Error::BuildServerConfig)?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(Error::BuildServerConfig)
}

#[derive(Debug)]
enum Error {
    WrongArgumentCount(usize),
    LoadCertFile(rustls::pki_types::pem::Error),
    LoadKeyFile(rustls::pki_types::pem::Error),
    BuildServerConfig(rustls::Error),
    RustlsBind(std::io::Error),
    RustlsRun(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WrongArgumentCount(argc) => {
                write!(f, "expected 3 arguments (incl arg 0), got {argc}")
            }
            Error::LoadCertFile(e) => write!(f, "error loading cert file: {e}"),
            Error::LoadKeyFile(e) => write!(f, "error loading key file: {e}"),
            Error::BuildServerConfig(e) => write!(f, "error building server config: {e}"),
            Error::RustlsBind(e) => write!(f, "failed binding: {e}"),
            Error::RustlsRun(e) => write!(f, "server aborted: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::WrongArgumentCount(_) => None,
            Error::LoadCertFile(e) => Some(e),
            Error::LoadKeyFile(e) => Some(e),
            Error::BuildServerConfig(e) => Some(e),
            Error::RustlsBind(e) => Some(e),
            Error::RustlsRun(e) => Some(e),
        }
    }
}
