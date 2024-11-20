//! SSH certificate parsing and verification.
//!
//! Support for parsing DER and PEM enconded SSH certificates. PEM decoding can be done in
//! place or not. All parsing is done in place, with zero allocations, for this,
//! the certificate data (DER) **MUST** outlive the parsed certificate.

const std = @import("std");
const proto = @import("proto.zig");

pub const Error = error{
    /// This indicates, either, PEM corruption, or certificate corruption.
    InvalidMagicString,
    /// As per spec, repeated extension are not allowed.
    RepeatedExtension,
    UnkownExtension,
} || proto.Error;

fn GenericIteratorImpl(comptime T: type, parse_value: anytype) type {
    return struct {
        ref: []const u8,
        off: usize,

        const Self = @This();

        pub fn next(self: *Self) T {
            if (self.done()) return null;

            const off, const ret = proto.rfc4251.parse_string(self.ref[self.off..]) catch
                return null;

            self.off += off;

            return parse_value(self.ref, &self.off, ret);
        }

        pub fn reset(self: *Self) void {
            self.off = 0;
        }

        pub fn done(self: *const Self) bool {
            return self.off == self.ref.len;
        }
    };
}

fn GenericIterator(comptime parse_value: anytype) type {
    const T = switch (@typeInfo(@TypeOf(parse_value))) {
        .@"fn" => |func| func.return_type.?,
        else => @compileError("Expected fn"),
    };

    return GenericIteratorImpl(T, parse_value);
}

pub const Pem = struct {
    magic: []const u8,
    der: []u8,
    comment: []const u8,

    pub inline fn tokenize(src: []const u8) std.mem.TokenIterator(u8, .any) {
        return std.mem.tokenizeAny(u8, src, " ");
    }
};

pub const Magic = enum(u3) {
    ssh_rsa,
    ssh_dsa,
    ecdsa_sha2_nistp256,
    ecdsa_sha2_nistp384,
    ecdsa_sha2_nistp521,
    ssh_ed25519,
    rsa_sha2_256,
    rsa_sha2_512,

    const Self = @This();

    const strings = proto.enum_to_str(Magic, "-cert-v01@openssh.com");

    pub fn as_string(self: *const Self) []const u8 {
        return strings[@intFromEnum(self.*)];
    }

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Magic) {
        const next, const magic = try proto.rfc4251.parse_string(src);

        for (Self.strings, 0..) |s, i|
            if (std.mem.eql(u8, s, magic))
                return .{ next, @enumFromInt(i) };

        return proto.Error.InvalidData;
    }

    pub fn from_slice(src: []const u8) Error!Magic {
        for (Self.strings, 0..) |s, i|
            if (std.mem.eql(u8, s, src))
                return @enumFromInt(i);

        return Error.InvalidMagicString;
    }

    pub fn from_bytes(src: []const u8) Error!Magic {
        _, const magic = Self.parse(src) catch return Error.InvalidMagicString;

        return magic;
    }
};

pub const CertType = enum(u2) {
    user = 1,
    host = 2,

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(CertType) {
        const next, const val = try proto.rfc4251.parse_int(u32, src);

        return .{ next, @enumFromInt(val) };
    }
};

/// The critical options section of the certificate specifies zero or more
/// options on the certificate's validity.
pub const CriticalOptions = struct {
    ref: []const u8 = undefined,

    const Self = @This();

    pub const Tags = enum {
        /// Specifies a command that is executed (replacing any the user specified
        /// on the ssh command-line) whenever this key is used for authentication.
        force_command,

        /// Comma-separated list of source addresses from which this certificate is
        /// accepted for authentication. Addresses are specified in CIDR format
        /// (nn.nn.nn.nn/nn or hhhh::hhhh/nn). If this option is not present, then
        /// certificates may be presented from any source address.
        source_address,

        /// Flag indicating that signatures made with this certificate must assert
        /// FIDO user verification (e.g. PIN or biometric). This option only makes
        /// sense for the U2F/FIDO security key types that support this feature in
        /// their signature formats.
        verify_required,

        pub const strings = proto.enum_to_str(Self.Tags, "");

        pub fn as_string(self: *const Self.Tags) []const u8 {
            return Self.Tag.strings[self.*];
        }
    };

    pub inline fn parse(buf: []const u8) proto.Error!proto.Cont(CriticalOptions) {
        const next, const ref = try proto.rfc4251.parse_string(buf);

        return .{ next, .{ .ref = ref } };
    }

    pub fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    pub const Iterator = GenericIterator(
        struct {
            // FIXME: Should return an error
            inline fn parse_value(ref: []const u8, off: *usize, key: []const u8) ?CriticalOption {
                const opt = Self.is_valid_option(key) orelse
                    return null;

                const next, const buf = proto.rfc4251.parse_string(ref[off.*..]) catch
                    return null;

                _, const value = proto.rfc4251.parse_string(buf) catch
                    return null;

                off.* += next;

                return .{ .kind = opt, .value = value };
            }
        }.parse_value,
    );

    inline fn is_valid_option(opt: []const u8) ?CriticalOptions.Tags {
        for (Self.Tags.strings, 0..) |s, i|
            if (std.mem.eql(u8, s, opt))
                return @enumFromInt(i);

        return null;
    }
};

pub const CriticalOption = struct {
    kind: CriticalOptions.Tags,
    value: []const u8,
};

/// The extensions section of the certificate specifies zero or more
/// non-critical certificate extensions.
pub const Extensions = struct {
    ref: []const u8 = undefined,

    const Self = @This();

    pub const Tags = enum(u8) {
        /// Flag indicating that signatures made with this certificate need not
        /// assert FIDO user presence. This option only makes sense for the
        /// U2F/FIDO security key types that support this feature in their
        /// signature formats.
        no_touch_required = 0x01 << 0,

        /// Flag indicating that X11 forwarding should be permitted. X11 forwarding
        /// will be refused if this option is absent.
        permit_X11_forwarding = 0x01 << 1,

        /// Flag indicating that agent forwarding should be allowed. Agent
        /// forwarding must not be permitted unless this option is present.
        permit_agent_forwarding = 0x01 << 2,

        /// Flag indicating that port-forwarding should be allowed. If this option
        /// is not present, then no port forwarding will be allowed.
        permit_port_forwarding = 0x01 << 3,

        /// Flag indicating that PTY allocation should be permitted. In the absence
        /// of this option PTY allocation will be disabled.
        permit_pty = 0x01 << 4,

        /// Flag indicating that execution of ~/.ssh/rc should be permitted.
        /// Execution of this script will not be permitted if this option is not
        /// present.
        permit_user_rc = 0x01 << 5,

        const strings = proto.enum_to_str(Self.Tags, "");

        pub inline fn as_string(self: *const Self.Tags) []const u8 {
            return Self.strings[@intFromEnum(self.*)];
        }
    };

    pub inline fn parse(buf: []const u8) proto.Error!proto.Cont(Extensions) {
        const next, const ref = try proto.rfc4251.parse_string(buf);

        return .{ next, .{ .ref = ref } };
    }

    pub fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    pub const Iterator = GenericIterator(
        struct {
            inline fn parse_value(ref: []const u8, off: *usize, key: []const u8) ?[]const u8 {
                // Skip empty pair
                if (ref.len != off.*) off.* += @sizeOf(u32);

                return key;
            }
        }.parse_value,
    );

    /// Returns the extensions as bitflags, checking if they are valid.
    pub fn to_bitflags(self: *const Self) Error!u8 {
        var ret: u8 = 0;

        var it = self.iter();

        outer: while (it.next()) |ext| {
            for (Self.Tags.strings, 0..) |ext_str, j| {
                if (std.mem.eql(u8, ext, ext_str)) {
                    const bit: u8 = (@as(u8, 0x01) << @as(u3, @intCast(j)));

                    if (ret & bit != 0)
                        return Error.RepeatedExtension;

                    ret |= bit;

                    continue :outer;
                }
            }

            return Error.UnkownExtension;
        }

        return ret;
    }
};

const Principals = struct {
    ref: []const u8,

    const Self = @This();

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Principals) {
        const next, const ref = try proto.rfc4251.parse_string(src);

        return .{ next, .{ .ref = ref } };
    }

    pub fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    pub const Iterator = GenericIterator(
        struct {
            inline fn parse_value(_: []const u8, _: *usize, key: []const u8) ?[]const u8 {
                return key;
            }
        }.parse_value,
    );
};

pub const RSA = struct {
    magic: Magic,
    nonce: []const u8,
    e: []const u8, // TODO: mpint
    n: []const u8, // TODO: mpint
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: Principals,
    valid_after: u64,
    valid_before: u64,
    critical_options: CriticalOptions,
    extensions: Extensions,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    const Self = @This();

    fn from(src: []const u8) Error!RSA {
        return try proto.parse(Self, src);
    }

    pub inline fn from_pem(pem: *const Pem) Error!RSA {
        return try Self.from(pem.der);
    }

    pub inline fn from_bytes(src: []const u8) Error!RSA {
        return try Self.from(src);
    }
};

pub const ECDSA = struct {
    magic: Magic,
    nonce: []const u8,
    curve: []const u8,
    public_key: []const u8,
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: Principals,
    valid_after: u64,
    valid_before: u64,
    critical_options: CriticalOptions,
    extensions: Extensions,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    const Self = @This();

    fn from(src: []const u8) Error!ECDSA {
        return try proto.parse(Self, src);
    }

    pub inline fn from_pem(pem: *const Pem) Error!ECDSA {
        return try Self.from(pem.der);
    }

    pub inline fn from_bytes(src: []const u8) Error!ECDSA {
        return try Self.from(src);
    }
};

pub const ED25519 = struct {
    magic: Magic,
    nonce: []const u8,
    pk: []const u8,
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: Principals,
    valid_after: u64,
    valid_before: u64,
    critical_options: CriticalOptions,
    extensions: Extensions,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    const Self = @This();

    fn from(src: []const u8) Error!ED25519 {
        return try proto.parse(Self, src);
    }

    pub inline fn from_pem(pem: *const Pem) Error!ED25519 {
        return try Self.from(pem.der);
    }

    pub inline fn from_bytes(src: []const u8) Error!ED25519 {
        return try Self.from(src);
    }
};

pub const Cert = union(enum) {
    rsa: RSA,
    ecdsa: ECDSA,
    ed25519: ED25519,

    const Self = @This();

    // TODO: from bytes...

    pub fn from_pem(pem: *const Pem) Error!Self {
        const magic = try Magic.from_slice(pem.magic);

        return switch (magic) {
            .ssh_rsa,
            .rsa_sha2_256,
            .rsa_sha2_512,
            => .{ .rsa = try RSA.from_pem(pem) },

            .ecdsa_sha2_nistp256,
            .ecdsa_sha2_nistp384,
            .ecdsa_sha2_nistp521,
            => .{ .ecdsa = try ECDSA.from_pem(pem) },

            .ssh_ed25519,
            => .{ .ed25519 = try ED25519.from_pem(pem) },

            else => @panic("DSA certificates are not supported"),
        };
    }
};
