use actix_web::{http::header::ContentType, HttpRequest, HttpResponse};
use rustls::NamedGroup;

/// simple handle
pub async fn handle(req: HttpRequest) -> HttpResponse {
    let named: Option<&NamedGroup> = req.conn_data();
    let group_name = named_group_string(named.unwrap());

    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(body(&group_name))
}

fn body(group_name: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Hello Bulma!</title>
    <link rel="stylesheet" href="/bulma.min.css">
  </head>
  <body>
  <section class="section">
    <div class="container">
      <section class="hero is-primary">
        <div class="hero-body">
          <h1 class="title">
            Hello World
          </h1>
          <h2 class="subtitle">
            My first website with <strong>Bulma</strong>!
          </h2>
        </div>
      </section>
      <section class="section">
        <h1 class="title">
          Connection Information
        </h1>
        <p>
          You connected using the handshake suite {group_name}
        </p>
      </section>
    </div>
  </section>
  </body>
</html>"#
    )
}

fn named_group_string(group: &NamedGroup) -> String {
    match group {
        NamedGroup::Unknown(0x11ec) => "Hybrid_ML-KEM_X25519".to_string(),
        other => format!("{other:?}"),
    }
}
