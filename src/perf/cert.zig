const std = @import("std");

const sshcrypto = @import("sshcrypto");

const MAX_RUNS: usize = 0x01 << 20;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    var pem = try sshcrypto.pem.CertificateDecoder
        .init(allocator, std.base64.standard.Decoder)
        .decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        _ = try sshcrypto.cert.RSA.from_bytes(pem.data.der);
    }

    const elapsed = timer.read();

    std.debug.print("`RSA.from_bytes` took ~= {}ns\n", .{elapsed / MAX_RUNS});
}
