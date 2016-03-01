extern crate ping_catch;
extern crate time;

use time::Duration;

#[allow(unused_must_use)]
fn main() {
    ping_catch::listen_during_and(Duration::seconds(30), |m| println!("{}", m));
}
