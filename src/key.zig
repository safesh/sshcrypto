const std = @import("std");

const proto = @import("proto.zig");

pub const Error = error{
    InvalidMagicString,
} || proto.Error;

pub const public = struct {
    pub const Magic = enum(u3) {
        ssh_rsa,
        ecdsa_sha2_nistp256,
        ecdsa_sha2_nistp384,
        ecdsa_sha2_nistp521,
        ssh_ed25519,

        const Self = @This();

        const strings = proto.enum_to_str(Self, "");

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

        pub fn from_bytes(src: []const u8) Error!Magic {
            _, const magic = Self.parse(src) catch return Error.InvalidMagicString;

            return magic;
        }
    };

    pub const Pem = struct {
        magic: []const u8,
        der: []u8,
        comment: []const u8,

        pub inline fn tokenize(src: []const u8) std.mem.TokenIterator(u8, .any) {
            return std.mem.tokenizeAny(u8, src, " ");
        }
    };

    pub const RSA = struct {
        magic: Magic,
        e: []const u8, // TODO: mpint
        n: []const u8, // TODO: mpint

        const Self = @This();

        fn from(src: []const u8) Error!RSA {
            return try proto.parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!RSA {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!RSA {
            // XXX: Check if PEM magic matches what we got from the DER
            return try Self.from(pem.der);
        }
    };

    pub const ECDSA = struct {
        magic: Magic,
        nonce: []const u8,
        curve: []const u8,

        const Self = @This();

        fn from(src: []const u8) Error!ECDSA {
            return try proto.parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!ECDSA {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!ECDSA {
            // XXX: Check if PEM magic matches what we got from the DER
            return try Self.from(pem.der);
        }
    };

    pub const ED25519 = struct {
        magic: Magic,
        pk: []const u8,

        const Self = @This();

        fn from(src: []const u8) Error!ED25519 {
            return try proto.parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!ED25519 {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!ED25519 {
            // XXX: Check if PEM magic matches what we got from the DER
            return try Self.from(pem.der);
        }
    };
};

pub const private = struct {
    pub const Magic = enum(u1) {
        openssh_key_v1,

        const Self = @This();

        const strings = proto.enum_to_str(Self, "");

        pub fn as_string(self: *const Self) []const u8 {
            return strings[@intFromEnum(self.*)];
        }

        pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Magic) {
            const next, const magic = try proto.read_null_terminated(src);

            for (Self.strings, 0..) |s, i|
                if (std.mem.eql(u8, s, magic))
                    return .{ next, @enumFromInt(i) };

            return proto.Error.InvalidData;
        }

        pub fn from_bytes(src: []const u8) Error!Magic {
            _, const magic = Self.parse(src) catch return Error.InvalidMagicString;

            return magic;
        }
    };

    pub const Pem = struct {
        _prefix: proto.Literal("BEGIN OPENSSH PRIVATE KEY"),
        der: []u8,
        _posfix: proto.Literal("END OPENSSH PRIVATE KEY"),

        pub inline fn tokenize(src: []const u8) std.mem.TokenIterator(u8, .sequence) {
            return std.mem.tokenizeSequence(u8, src, "-----");
        }
    };

    pub const RSA = struct {
        magic: Magic,
        chipher_name: []const u8,
        kdf_name: []const u8,
        kdf: u32,
        number_of_keys: u32,
        public_key: []const u8,
        private_key: []const u8, // TODO: parts

        const Self = @This();

        pub fn from(src: []const u8) Error!RSA {
            return try proto.parse(Self, src);
        }
    };
};
