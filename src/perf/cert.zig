const std = @import("std");
const sshk = @import("sshkeys");

const sshcert = sshk.cert;

const Timer = std.time.Timer;

const MAX_RUNS: usize = 4096;

test "benchmark rsa `from_bytes`" {
    var pem = try sshk.Decoder(sshcert.Pem).init(
        std.testing.allocator,
        std.base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    var sum: u64 = 0;

    var timer = try Timer.start();

    for (0..MAX_RUNS) |_| {
        _ = try sshcert.RSA.from_bytes(pem.data.der);

        sum += timer.lap();
    }

    std.debug.print("rsa `from_bytes` took ~= {}ns\n", .{sum / MAX_RUNS});
}
