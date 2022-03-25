use std::borrow::Cow;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct ClientCommands {
    pub messages: Vec<ClientCommand>,
}

#[derive(Deserialize, Serialize)]
pub struct ClientResponses<'a> {
    #[serde(borrow)]
    pub messages: Vec<ClientResponse<'a>>,
}

#[derive(Deserialize, Serialize)]
pub enum ClientCommand {
    SetPort { port: u16 },
}

#[derive(Deserialize, Serialize)]
pub enum ClientResponse<'a> {
    PortSet { port: u16 },
    Error { msg: Cow<'a, str> },
}
