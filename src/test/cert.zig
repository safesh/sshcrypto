const std = @import("std");

const sshcrypto = @import("sshcrypto");

const sshcert = sshcrypto.cert;

const expect = std.testing.expect;
const expect_equal = std.testing.expectEqual;
const expect_error = std.testing.expectError;

const Decoder = sshcrypto.Decoder(sshcert.Pem);

test "parse rsa cert" {
    var pem = try sshcrypto.pem.CertificateDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    switch (try sshcert.Cert.from_pem(&pem.data)) {
        .rsa => |cert| {
            try expect_equal(cert.magic, sshcert.Magic.ssh_rsa);
            try expect_equal(cert.serial, 2);
            try expect_equal(cert.kind, sshcert.CertType.user);
            try expect(std.mem.eql(u8, cert.key_id, "abc"));

            var it = cert.valid_principals.iter();
            try expect(std.mem.eql(u8, it.next().?, "root"));
            try expect(it.done());

            try expect_equal(cert.valid_after, 0);
            try expect_equal(cert.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "parse rsa cert bad cert" {
    var pem = try sshcrypto.pem.CertificateDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    const len = pem.data.der.len;
    pem.data.der.len = 100;

    const cert = sshcert.Cert.from_pem(&pem.data);

    pem.data.der.len = len;

    try expect_error(sshcert.Error.MalformedString, cert);
}

test "parse ecdsa cert" {
    var pem = try sshcrypto.pem.CertificateDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("ecdsa-cert.pub"));
    defer pem.deinit();

    switch (try sshcert.Cert.from_pem(&pem.data)) {
        .ecdsa => |cert| {
            try expect_equal(cert.magic, sshcert.Magic.ecdsa_sha2_nistp256);
            try expect_equal(cert.serial, 2);
            try expect_equal(cert.kind, sshcert.CertType.user);
            try expect(std.mem.eql(u8, cert.key_id, "abc"));

            var it = cert.valid_principals.iter();
            try expect(std.mem.eql(u8, it.next().?, "root"));
            try expect(it.done());

            try expect_equal(cert.valid_after, 0);
            try expect_equal(cert.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "parse ed25519 cert" {
    var pem = try sshcrypto.pem.CertificateDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("ed25519-cert.pub"));
    defer pem.deinit();

    switch (try sshcert.Cert.from_pem(&pem.data)) {
        .ed25519 => |cert| {
            try expect_equal(cert.magic, sshcert.Magic.ssh_ed25519);
            try expect_equal(cert.serial, 2);
            try expect_equal(cert.kind, sshcert.CertType.user);

            try expect(std.mem.eql(u8, cert.key_id, "abc"));

            var it = cert.valid_principals.iter();
            try expect(std.mem.eql(u8, it.next().?, "root"));
            try expect(it.done());

            try expect_equal(cert.valid_after, 0);
            try expect_equal(cert.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "extensions iterator" {
    // Reference
    const extensions = [_][]const u8{
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    };

    var pem = try sshcrypto.pem.CertificateDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    const rsa = try sshcert.RSA.from_pem(&pem.data);

    var it = rsa.extensions.iter();

    for (extensions) |extension| {
        try expect(std.mem.eql(u8, extension, it.next().?));
    }

    try expect(it.done());
}

test "extensions to bitflags" {
    const Ext = sshcert.Extensions.Tags;

    var pem = try sshcrypto.pem.CertificateDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    const rsa = try sshcert.RSA.from_pem(&pem.data);

    try expect_equal(
        try rsa.extensions.to_bitflags(),
        @intFromEnum(Ext.permit_agent_forwarding) |
            @intFromEnum(Ext.permit_X11_forwarding) |
            @intFromEnum(Ext.permit_user_rc) |
            @intFromEnum(Ext.permit_port_forwarding) |
            @intFromEnum(Ext.permit_pty),
    );
}

test "multiple valid principals iterator" {
    // Reference
    const valid_principals = [_][]const u8{
        "foo",
        "bar",
        "baz",
    };

    var pem = try sshcrypto.pem.CertificateDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("multiple-principals-cert.pub"));
    defer pem.deinit();

    const rsa = try sshcert.RSA.from_pem(&pem.data);

    var it = rsa.valid_principals.iter();

    for (valid_principals) |principal|
        try expect(std.mem.eql(u8, principal, it.next().?));
}

test "critical options iterator" {
    // Reference
    const critical_options = [_]sshcert.CriticalOption{.{
        .kind = .force_command,
        .value = "ls -la",
    }};

    var pem = try sshcrypto.pem.CertificateDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("force-command-cert.pub"));
    defer pem.deinit();

    const rsa = try sshcert.RSA.from_pem(&pem.data);

    var it = rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        try expect_equal(critical_option.kind, opt.kind);
        try expect(std.mem.eql(u8, critical_option.value, opt.value));
    }

    try expect(it.done());
}

test "multiple critical options iterator" {
    // Reference
    const critical_options = [_]sshcert.CriticalOption{
        .{
            .kind = .force_command,
            .value = "ls -la",
        },
        .{
            .kind = .source_address,
            .value = "198.51.100.0/24,203.0.113.0/26",
        },
    };

    var pem = try sshcrypto.pem.CertificateDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("multiple-critical-options-cert.pub"));
    defer pem.deinit();

    const rsa = try sshcert.RSA.from_pem(&pem.data);

    var it = rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        try expect_equal(critical_option.kind, opt.kind);
        try expect(std.mem.eql(u8, critical_option.value, opt.value));
    }

    try expect(it.done());
}
