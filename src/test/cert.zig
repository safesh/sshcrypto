const std = @import("std");

const sshk = @import("sshkeys");

const sshcert = sshk.cert;

const testing = std.testing;
const base64 = std.base64;

const expectEqual = std.testing.expectEqual;
const expect = std.testing.expect;

const Decoder = sshk.Decoder(sshcert.Pem);

test "parse rsa cert" {
    var pem = try Decoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer std.testing.allocator.free(pem.der);

    switch (try sshcert.Cert.from_pem(&pem)) {
        .rsa => |cert| {
            try expectEqual(cert.magic, sshcert.Magic.ssh_rsa);
            try expectEqual(cert.serial, 2);
            try expectEqual(cert.kind, sshcert.CertType.user);
            try expect(std.mem.eql(u8, cert.key_id, "abc"));

            var it = cert.valid_principals.iter();
            try expect(std.mem.eql(u8, it.next().?, "root"));
            try expect(it.done());

            try expectEqual(cert.valid_after, 0);
            try expectEqual(cert.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "parse rsa cert bad cert" {
    var pem = try Decoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer std.testing.allocator.free(pem.der);

    const len = pem.der.len;
    pem.der.len = 100;

    const cert = sshcert.Cert.from_pem(&pem);

    pem.der.len = len;

    try testing.expectError(sshcert.Error.MalformedString, cert);
}

test "parse ecdsa cert" {
    var pem = try Decoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("ecdsa-cert.pub"));
    defer std.testing.allocator.free(pem.der);

    switch (try sshcert.Cert.from_pem(&pem)) {
        .ecdsa => |cert| {
            try expectEqual(cert.magic, sshcert.Magic.ecdsa_sha2_nistp256);
            try expectEqual(cert.serial, 2);
            try expectEqual(cert.kind, sshcert.CertType.user);
            try expect(std.mem.eql(u8, cert.key_id, "abc"));

            var it = cert.valid_principals.iter();
            try expect(std.mem.eql(u8, it.next().?, "root"));
            try expect(it.done());

            try expectEqual(cert.valid_after, 0);
            try expectEqual(cert.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "parse ed25519 cert" {
    var pem = try Decoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("ed25519-cert.pub"));
    defer std.testing.allocator.free(pem.der);

    switch (try sshcert.Cert.from_pem(&pem)) {
        .ed25519 => |cert| {
            try expectEqual(cert.magic, sshcert.Magic.ssh_ed25519);
            try expectEqual(cert.serial, 2);
            try expectEqual(cert.kind, sshcert.CertType.user);

            try expect(std.mem.eql(u8, cert.key_id, "abc"));

            var it = cert.valid_principals.iter();
            try expect(std.mem.eql(u8, it.next().?, "root"));
            try expect(it.done());

            try expectEqual(cert.valid_after, 0);
            try expectEqual(cert.valid_before, std.math.maxInt(u64));
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

    var pem = try Decoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer std.testing.allocator.free(pem.der);

    const rsa = try sshcert.RSA.from_pem(&pem);

    var it = rsa.extensions.iter();

    for (extensions) |extension| {
        try expect(std.mem.eql(u8, extension, it.next().?));
    }

    try expect(it.done());
}

test "extensions to bitflags" {
    const Ext = sshcert.Extensions.Tags;

    var pem = try Decoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer std.testing.allocator.free(pem.der);

    const rsa = try sshcert.RSA.from_pem(&pem);

    try expectEqual(
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

    var pem = try Decoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("multiple-principals-cert.pub"));
    defer std.testing.allocator.free(pem.der);

    const rsa = try sshcert.RSA.from_pem(&pem);

    var it = rsa.valid_principals.iter();

    for (valid_principals) |principal| {
        try expect(std.mem.eql(u8, principal, it.next().?));
    }
}

test "critical options iterator" {
    // Reference
    const critical_options = [_]sshcert.CriticalOption{.{
        .kind = .force_command,
        .value = "ls -la",
    }};

    var pem = try Decoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("force-command-cert.pub"));
    defer std.testing.allocator.free(pem.der);

    const rsa = try sshcert.RSA.from_pem(&pem);

    var it = rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        try expectEqual(critical_option.kind, opt.kind);
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

    var pem = try Decoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("multiple-critical-options-cert.pub"));
    defer std.testing.allocator.free(pem.der);

    const rsa = try sshcert.RSA.from_pem(&pem);

    var it = rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        try expectEqual(critical_option.kind, opt.kind);
        try expect(std.mem.eql(u8, critical_option.value, opt.value));
    }

    try expect(it.done());
}
