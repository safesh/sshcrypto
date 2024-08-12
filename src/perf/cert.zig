const std = @import("std");
const sshk = @import("sshkeys");

const testing = std.testing;

const Timer = std.time.Timer;

const debug = std.debug.print;

const MAX_RUNS: usize = 4096;

test "benchmark rsa `from_bytes`" {
    var der = try sshk.PemDecoder.init(
        testing.allocator,
        std.base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer der.deinit();

    var sum: u64 = 0;

    var timer = try Timer.start();

    for (0..MAX_RUNS) |_| {
        _ = try sshk.RSA.from_bytes(der.ref);

        sum += timer.lap();
    }

    debug("rsa `from_bytes` took ~= {}ns\n", .{sum / MAX_RUNS});
}
