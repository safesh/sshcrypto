const std = @import("std");

const sshk = @import("sshkeys");

const testing = std.testing;
const base64 = std.base64;

const expectEqual = std.testing.expectEqual;
const expect = std.testing.expect;

test "parse rsa cert" {
    var der = try sshk.PemDecoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer der.deinit();

    switch (try sshk.Cert.from_der(&der)) {
        .rsa => |cert| {
            try expectEqual(cert.magic, sshk.Magic.ssh_rsa);
            try expectEqual(cert.serial, 2);
            try expectEqual(cert.kind, sshk.CertType.user);
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
    var der = try sshk.PemDecoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer der.deinit();

    const len = der.ref.len;
    der.ref.len = 100;

    const cert = sshk.Cert.from_der(&der);

    der.ref.len = len;

    try testing.expectError(sshk.Error.MalformedString, cert);
}

test "parse ecdsa cert" {
    var der = try sshk.PemDecoder.init(testing.allocator, base64.standard.Decoder).decode(@embedFile("ecdsa-cert.pub"));
    defer der.deinit();

    switch (try sshk.Cert.from_der(&der)) {
        .ecdsa => |cert| {
            try expectEqual(cert.magic, sshk.Magic.ecdsa_sha2_nistp256);
            try expectEqual(cert.serial, 2);
            try expectEqual(cert.kind, sshk.CertType.user);
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
    var der = try sshk.PemDecoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("ed25519-cert.pub"));
    defer der.deinit();

    switch (try sshk.Cert.from_der(&der)) {
        .ed25519 => |cert| {
            try expectEqual(cert.magic, sshk.Magic.ssh_ed25519);
            try expectEqual(cert.serial, 2);
            try expectEqual(cert.kind, sshk.CertType.user);

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

    var der = try sshk.PemDecoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer der.deinit();

    const rsa = try sshk.RSA.from_der(&der);

    var it = rsa.extensions.iter();

    for (extensions) |extension| {
        try expect(std.mem.eql(u8, extension, it.next().?));
    }

    try expect(it.done());
}

test "extensions to bitflags" {
    const Ext = sshk.Extensions.Tags;

    var der = try sshk.PemDecoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("rsa-cert.pub"));
    defer der.deinit();

    const rsa = try sshk.RSA.from_der(&der);

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

    var der = try sshk.PemDecoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("multiple-principals-cert.pub"));
    defer der.deinit();

    const rsa = try sshk.RSA.from_der(&der);

    var it = rsa.valid_principals.iter();

    for (valid_principals) |principal| {
        try expect(std.mem.eql(u8, principal, it.next().?));
    }
}

test "critical options iterator" {
    // Reference
    const critical_options = [_]sshk.CriticalOption{.{
        .kind = .force_command,
        .value = "ls -la",
    }};

    var der = try sshk.PemDecoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("force-command-cert.pub"));
    defer der.deinit();

    const rsa = try sshk.RSA.from_der(&der);

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
    const critical_options = [_]sshk.CriticalOption{
        .{
            .kind = .force_command,
            .value = "ls -la",
        },
        .{
            .kind = .source_address,
            .value = "198.51.100.0/24,203.0.113.0/26",
        },
    };

    var der = try sshk.PemDecoder.init(
        testing.allocator,
        base64.standard.Decoder,
    ).decode(@embedFile("multiple-critical-options-cert.pub"));
    defer der.deinit();

    const rsa = try sshk.RSA.from_der(&der);

    var it = rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        try expectEqual(critical_option.kind, opt.kind);
        try expect(std.mem.eql(u8, critical_option.value, opt.value));
    }

    try expect(it.done());
}
