use std::sync::Arc;

use actix_web::{
    http::header::ContentType, middleware, web, App, HttpRequest, HttpResponse, HttpServer,
};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    NamedGroup, ServerConfig, DEFAULT_VERSIONS,
};

/// simple handle
async fn index(req: HttpRequest) -> HttpResponse {
    println!("{req:?}");
    let named: Option<&NamedGroup> = req.conn_data();
    println!("{named:?}");
    let group_name = named.unwrap();

    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(format!(
            r#"<!DOCTYPE html><html><body>
            <p>Welcome to your TLS-secured homepage!</p>
            <p>you are connecting using kx group {group_name:?}</p>
        </body></html>"#
        ))
}

type TlsSession = actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let config = load_rustls_config().unwrap();

    log::info!("starting HTTPS server at https://localhost:8443");

    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            // register simple handler, handle all methods
            .service(web::resource("/index.html").to(index))
            .service(web::redirect("/", "/index.html"))
    })
    .on_connect(|session, extensions| {
        let (_, conn) = session.downcast_ref::<TlsSession>().unwrap().get_ref();
        let group = conn.negotiated_key_exchange_group().unwrap();
        let name = group.name();
        println!("in on_connect. name: {name:?}");
        extensions.insert(name);
    })
    .bind_rustls_0_23("127.0.0.1:8443", config)?
    .run()
    .await
}

fn load_rustls_config() -> Result<ServerConfig, rustls::Error> {
    let mut args = std::env::args();
    args.next();
    let cert_file = args.next().expect("missing certificate file argument");
    let private_key_file = args.next().expect("missing private key file argument");

    let certs = CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();

    ServerConfig::builder_with_provider(Arc::new(rustls_libcrux_provider::provider()))
        .with_protocol_versions(DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
}
