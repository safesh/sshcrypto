const std = @import("std");
const cert = @import("mod.zig");

const testing = std.testing;

const Decoder = std.base64.standard.Decoder;
const Timer = std.time.Timer;

const debug = std.debug.print;

const MAX_RUNS: usize = 4096;

test "benchmark rsa `from_bytes`" {
    var der = try cert.PemDecoder.init(testing.allocator, Decoder).decode(@embedFile("test/rsa-cert.pub"));
    defer der.deinit();

    var sum: u64 = 0;

    var timer = try Timer.start();

    for (0..MAX_RUNS) |_| {
        _ = try cert.RSA.from_bytes(der.ref);

        sum += timer.lap();
    }

    debug("rsa `from_bytes` took ~= {}ns\n", .{sum / MAX_RUNS});
}
