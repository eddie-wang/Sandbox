use serde::Serialize;

#[derive(Serialize)]
pub struct Health {
    pub service: &'static str,
    pub live: bool,
}
