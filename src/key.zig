const std = @import("std");

const proto = @import("proto.zig");

pub const Error = error{
    /// This indicates, either, PEM corruption, or key corruption.
    InvalidMagicString,
    /// The checksum for private keys is invalid, meaning either,
    /// decryption was not successful, or data is corrupted. This is NOT an auth
    /// form error.
    InvalidChecksum,
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
    pub fn Managed(comptime T: type) type {
        return struct {
            allocator: ?std.mem.Allocator,
            ref: []u8,
            data: T,

            const Self = @This();

            pub fn deinit(self: *Self) void {
                // NOTE: Not so sure if this makes any sense, but it's better not to leak this memory
                if (self.allocator) |allocator| {
                    std.crypto.secureZero(u8, self.ref);
                    allocator.free(self.ref);
                }
            }
        };
    }

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

    pub const Cipher = struct {
        name: []const u8,
        block_size: u32,
        key_len: u32,
        iv_len: u32,
        auth_len: u32,

        const Self = @This();

        const ciphers = [_]Self{
            // Taken from openssl-portable
            // TODO: Add OpenSSL ciphers
            // .{ "openssl-3des-cbc", 8, 24, 0, 0 },
            // .{ "openssl-aes128-cbc", 16, 16, 0, 0 },
            // .{ "openssl-aes192-cbc", 16, 24, 0, 0 },
            // .{ "openssl-aes256-cbc", 16, 32, 0, 0 },
            // .{ "openssl-aes128-ctr", 16, 16, 0, 0 },
            // .{ "openssl-aes192-ctr", 16, 24, 0, 0 },
            // .{ "openssl-aes256-ctr", 16, 32, 0, 0 },
            // .{ "openssl-aes128-gcm@openssh.com", 16, 16, 12, 16 },
            // .{ "openssl-aes256-gcm@openssh.com", 16, 32, 12, 16 },
            .{ .name = "aes128-ctr", .block_size = 16, .key_len = 16, .iv_len = 0, .auth_len = 0 },
            .{ .name = "aes192-ctr", .block_size = 16, .key_len = 24, .iv_len = 0, .auth_len = 0 },
            .{ .name = "aes256-ctr", .block_size = 16, .key_len = 32, .iv_len = 0, .auth_len = 0 },
            .{ .name = "chacha20-poly1305@openssh.com", .block_size = 8, .key_len = 64, .iv_len = 0, .auth_len = 16 },
            .{ .name = "none", .block_size = 8, .key_len = 0, .iv_len = 0, .auth_len = 0 },
        };

        pub fn get_supported_ciphers() [ciphers.len][]const u8 {
            comptime var ret: [ciphers.len][]const u8 = undefined;

            comptime var i = 0;
            inline for (comptime ciphers) |cipher| {
                ret[i] = cipher.name;

                i += 1;
            }

            return ret;
        }

        pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Cipher) {
            const next, const name = try proto.rfc4251.parse_string(src);

            for (Self.ciphers) |cipher| {
                if (std.mem.eql(u8, name, cipher.name)) {
                    return .{ next, cipher };
                }
            }

            return proto.Error.InvalidData;
        }
    };

    /// "Newer" OpenSSH private key format. Will NOT work with old PKCS #1 or SECG keys.
    pub const Pem = struct {
        _prefix: proto.Literal("BEGIN OPENSSH PRIVATE KEY"),
        der: []u8,
        _posfix: proto.Literal("END OPENSSH PRIVATE KEY"),

        pub inline fn tokenize(src: []const u8) std.mem.TokenIterator(u8, .sequence) {
            return std.mem.tokenizeSequence(u8, src, "-----");
        }
    };

    pub const Kdf = struct {
        salt: []const u8,
        rounds: u32,

        const Self = @This();

        pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Kdf) {
            const next, const kdf = try proto.rfc4251.parse_string(src);

            if (kdf.len == 0)
                // FIXME: We should return an optional here, to do so need to
                // allow the generic parser to support optional types.
                return .{ next, undefined };

            return .{ next, try proto.parse(Self, kdf) };
        }

        // NOTE: Hack while we wait for zig
        pub inline fn intersperse_key(keyiv: []u8) []u8 {
            var a = std.mem.zeroes([24]u8);
            var b = std.mem.zeroes([24]u8);

            @memcpy(a[0..24], keyiv[0..24]);
            @memcpy(b[0..24], keyiv[32..56]);

            var i: u32 = 0;
            for (a, b) |p, q| {
                keyiv[i] = p;
                keyiv[i + 1] = q;

                i += 2;
            }

            return keyiv[0..48];
        }
    };

    pub const RSA = struct {
        magic: Magic,
        cipher: Cipher,
        kdf_name: []const u8,
        kdf: Kdf, // TODO: Make this optional
        number_of_keys: u32,
        public_key_blob: []const u8,
        private_key_blob: []const u8,

        const Self = @This();

        pub const Key = struct {
            checksum: u64, // TODO: Check this a parse
            kind: []const u8,
            // Public key parts
            n: []const u8,
            e: []const u8,
            // Private key parts
            d: []const u8,
            i: []const u8,
            p: []const u8,
            q: []const u8,
            comment: []const u8,

            _pad: proto.Padding,

            pub fn check_checksum(self: *const Key) bool {
                return @as(u32, @truncate(self.checksum >> @bitSizeOf(u32))) ==
                    @as(u32, @truncate(self.checksum));
            }

            fn from(src: []const u8) Error!Key {
                const key = try proto.parse(Key, src);

                if (!key.check_checksum()) return error.InvalidChecksum;

                return key;
            }
        };

        pub fn get_public_key(self: *const Self) !public.RSA {
            return public.RSA.from(self.public_key_blob);
        }

        /// Returns `true` if the `private_key_blob` is encrypted, i.e., cipher.name != "none"
        pub inline fn is_encrypted(self: *const Self) bool {
            return !std.mem.eql(u8, self.cipher.name, "none");
        }

        pub fn get_private_key(
            self: *const Self,
            allocator: std.mem.Allocator,
            passphrase: ?[]const u8,
        ) !Managed(Key) {
            if (self.is_encrypted() and passphrase == null)
                return error.MissingPassphrase;

            // TODO: Make this generic.
            if (std.mem.eql(u8, self.cipher.name, "aes256-ctr")) {
                const out = try allocator.alloc(u8, self.private_key_blob.len);
                errdefer allocator.free(out);

                var keyiv = std.mem.zeroes([32 + 32]u8);
                errdefer std.crypto.secureZero(u8, &keyiv);

                try std.crypto.pwhash.bcrypt.pbkdf(
                    passphrase.?,
                    self.kdf.salt,
                    &keyiv,
                    self.kdf.rounds,
                );

                const fixed_keyiv = Kdf.intersperse_key(&keyiv);

                const key: [32]u8 = fixed_keyiv[0..32].*;
                const iv: [16]u8 = fixed_keyiv[32..48].*;

                const ctx = std.crypto.core.aes.Aes256.initEnc(key);
                std.crypto.core.modes.ctr(
                    std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256),
                    ctx,
                    out,
                    self.private_key_blob,
                    iv,
                    std.builtin.Endian.big,
                );

                return .{
                    .allocator = allocator,
                    .ref = out,
                    .data = try Key.from(out),
                };
            }

            return .{
                .allocator = null,
                .ref = undefined,
                .data = try Key.from(self.private_key_blob),
            };
        }

        fn from(src: []const u8) Error!RSA {
            return try proto.parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!RSA {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!RSA {
            return try Self.from(pem.der);
        }
    };
};
