# ping_catcher
ping_catcher is a simple program wich will listen for ping on your computer

To run it you'll need [cargo](github.com/rust-lang/cargo/), the rust package manager. Then :
```
$ git clone git@github.com:leonard-IMBERT/ping_catcher.git
$ cd ping_catcher/
$ sudo cargo run
```

Thanks to [teisenbe/rust-traceroute](github.com/teisenbe/rust-traceroute) for his code wich help me a lot and thanks to [Geal/nom](github.com/Geal/nom) for help me parsing ICMP message.
