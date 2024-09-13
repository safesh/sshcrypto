const std = @import("std");

const sshcrypto = @import("sshcrypto");
const sshcert = sshcrypto.cert;

const Timer = std.time.Timer;

const MAX_RUNS: usize = 0x1 << 18;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer {
        if (gpa.deinit() == .leak) @panic("LEAK");
    }

    var pem = try sshcrypto.Decoder(sshcert.Pem).init(
        allocator,
        std.base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    var timer = try Timer.start();

    for (0..MAX_RUNS) |_| {
        _ = try sshcert.RSA.from_bytes(pem.data.der);
    }

    const elapsed = timer.read();

    std.debug.print("rsa `from_bytes` took ~= {}ns\n", .{elapsed / MAX_RUNS});
}
