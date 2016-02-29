extern crate ping_catch;
extern crate time;

use time::Duration;

fn main() {
    ping_catch::listen_during(Duration::minutes(5));
}
