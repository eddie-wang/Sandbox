use axum::{Json, extract::{Path, rejection::{JsonRejection, PathRejection}}};
use serde::Serialize;

use crate::{http::{self, ApiError}, model::{CaptureRequest, ExecRequest, valid_id}};

#[derive(Serialize)]
pub struct Health {
    pub service: &'static str,
    pub live: bool,
}

pub async fn exec(id: Result<Path<String>, PathRejection>, input: Result<Json<ExecRequest>, JsonRejection>) -> Result<(), ApiError> {
    let Path(id) = id.map_err(|_| http::invalid_input())?;
    let request = http::json(input)?;
    if !valid_id(&id) || !request.valid() {
        return Err(http::invalid_input());
    }
    Err(http::not_implemented())
}

pub async fn capture(id: Result<Path<String>, PathRejection>, input: Result<Json<CaptureRequest>, JsonRejection>) -> Result<(), ApiError> {
    let Path(id) = id.map_err(|_| http::invalid_input())?;
    let request = http::json(input)?;
    if !valid_id(&id) || !valid_id(&request.template_id) {
        return Err(http::invalid_input());
    }
    // The enum is deserialized strictly, but no capture backend is invoked.
    let _ = request.runtime;
    Err(http::not_implemented())
}
