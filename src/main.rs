mod config;
mod handlers;
mod logger;
mod mime;
mod request;
mod response;
mod router;
mod server;
mod utils;

use config::Config;
use server::Server;

fn main() {
    let config = Config::new();

    let mut server = Server::new(config);

    server.run();
}
