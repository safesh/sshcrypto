const std = @import("std");

const proto = @import("proto.zig");

pub const Error = error{
    /// This indicates, either: PEM corruption, DER corruption, or an
    /// unsupported magic string.
    InvalidMagicString,
    /// The checksum for private keys is invalid, meaning either, decryption
    /// was not successful, or data is corrupted. This is NOT an auth form
    /// error.
    InvalidChecksum,
} || proto.Error || std.mem.Allocator.Error;

pub const public = struct {
    /// NOTE: DSA keys are not supported
    pub const Magic = enum(u3) {
        ssh_rsa,
        ecdsa_sha2_nistp256,
        ecdsa_sha2_nistp384,
        ecdsa_sha2_nistp521,
        ssh_ed25519,

        const Self = @This();

        const strings = proto.enum_to_str(Self, "");

        pub inline fn as_string(self: *const Self) []const u8 {
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

    // TODO: add support for FIDO2/U2F keys

    pub const Pem = struct {
        magic: []const u8,
        der: []u8,
        comment: proto.Blob([]const u8),

        pub inline fn tokenize(src: []const u8) std.mem.TokenIterator(u8, .any) {
            return std.mem.tokenizeAny(u8, src, " ");
        }
    };

    pub const Rsa = struct {
        magic: Magic,
        e: []const u8, // TODO: mpint
        n: []const u8, // TODO: mpint

        const Self = @This();

        fn from(src: []const u8) Error!Rsa {
            return try proto.parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!Rsa {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!Rsa {
            // XXX: Check if PEM magic matches what we got from the DER
            return try Self.from(pem.der);
        }
    };

    pub const Ecdsa = struct {
        magic: Magic,
        nonce: []const u8,
        curve: []const u8,

        const Self = @This();

        fn from(src: []const u8) Error!Ecdsa {
            return try proto.parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!Ecdsa {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!Ecdsa {
            // XXX: Check if PEM magic matches what we got from the DER
            return try Self.from(pem.der);
        }
    };

    pub const Ed25519 = struct {
        magic: Magic,
        pk: []const u8,

        const Self = @This();

        fn from(src: []const u8) Error!Ed25519 {
            return try proto.parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!Ed25519 {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!Ed25519 {
            // XXX: Check if PEM magic matches what we got from the DER
            return try Self.from(pem.der);
        }
    };
};

pub const private = struct {
    pub fn Managed(comptime T: type) type {
        return struct {
            allocator: std.mem.Allocator,
            ref: []u8,
            data: T,

            const Self = @This();

            pub fn deinit(self: *Self) void {
                std.crypto.secureZero(u8, self.ref);
                self.allocator.free(self.ref);
            }
        };
    }

    pub const Magic = enum(u1) {
        openssh_key_v1,

        const Self = @This();

        const strings = proto.enum_to_str(Self, "");

        pub inline fn as_string(self: *const Self) []const u8 {
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

    pub fn decrypt_aes_256_ctr(
        allocator: std.mem.Allocator,
        private_key_blob: []const u8,
        kdf: *const Kdf,
        passphrase: []const u8,
    ) Error![]u8 {
        const KEYLEN: u32 = 32;
        const IVLEN: u32 = 16;

        const out = try allocator.alloc(u8, private_key_blob.len);
        errdefer allocator.free(out);

        var keyiv = std.mem.zeroes([KEYLEN + IVLEN]u8);
        defer std.crypto.secureZero(u8, &keyiv);

        std.crypto.pwhash.bcrypt.opensshKdf(
            passphrase,
            kdf.salt,
            &keyiv,
            kdf.rounds,
        ) catch return Error.InvalidData; // FIXME;

        const ctx = std.crypto.core.aes.Aes256.initEnc(keyiv[0..KEYLEN].*);
        std.crypto.core.modes.ctr(
            std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256),
            ctx,
            out,
            private_key_blob,
            keyiv[KEYLEN..keyiv.len].*,
            std.builtin.Endian.big,
        );

        return out;
    }

    pub fn decrypt_none(allocator: std.mem.Allocator, private_key_blob: []const u8, _: *const Kdf, _: []const u8) Error![]u8 {
        const out = try allocator.alloc(u8, private_key_blob.len);
        errdefer allocator.free(out);

        @memcpy(out, private_key_blob);

        return out;
    }

    pub const Cipher = struct {
        name: []const u8,
        decrypt: *const fn (
            allocator: std.mem.Allocator,
            private_key_blob: []const u8,
            kdf: *const Kdf,
            passphrase: []const u8,
        ) Error![]u8,

        const Self = @This();

        pub const ciphers = [_]Self{
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
            // .{ .name = "aes128-ctr", .block_size = 16, .key_len = 16, .iv_len = 0, .auth_len = 0 },
            // .{ .name = "aes192-ctr", .block_size = 16, .key_len = 24, .iv_len = 0, .auth_len = 0 },
            .{ .name = "aes256-ctr", .decrypt = &decrypt_aes_256_ctr },
            // .{ .name = "chacha20-poly1305@openssh.com", .block_size = 8, .key_len = 64, .iv_len = 0, .auth_len = 16 },
            .{ .name = "none", .decrypt = &decrypt_none },
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

            inline for (comptime Self.ciphers) |cipher| {
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
    };

    inline fn check_checksum(checksum: u64) bool {
        return @as(u32, @truncate(std.math.shr(u64, checksum, @bitSizeOf(u32)))) ==
            @as(u32, @truncate(checksum));
    }

    pub fn PrivateKey(comptime Pub: type, comptime Pri: type) type {
        return struct {
            magic: Magic,
            cipher: Cipher,
            kdf_name: []const u8,
            kdf: Kdf, // TODO: Make this optional
            number_of_keys: u32,
            public_key_blob: []const u8,
            private_key_blob: []const u8,

            const Self = @This();

            /// Returns `true` if the `private_key_blob` is encrypted, i.e.,
            /// cipher.name != "none"
            pub inline fn is_encrypted(self: *const Self) bool {
                return !std.mem.eql(u8, self.cipher.name, "none");
            }

            pub fn get_public_key(self: *const Self) !Pub {
                if (!@hasDecl(Pub, "from_bytes"))
                    @compileError("Type `Pub` does not declare `from_bytes([]const u8)`");

                return Pub.from_bytes(self.public_key_blob);
            }

            pub fn get_private_key(
                self: *const Self,
                allocator: std.mem.Allocator,
                passphrase: ?[]const u8,
            ) !Managed(Pri) {
                if (!@hasDecl(Pri, "from_bytes"))
                    @compileError("Type `Pri` does not declare `from_bytes([]const u8)`");

                if (self.is_encrypted() and passphrase == null)
                    return error.MissingPassphrase;

                inline for (comptime private.Cipher.ciphers) |cipher| {
                    if (std.mem.eql(u8, cipher.name, self.cipher.name)) {
                        const private_blob = try cipher.decrypt(
                            allocator,
                            self.private_key_blob,
                            &self.kdf,
                            passphrase orelse undefined,
                        );

                        return .{
                            .allocator = allocator,
                            .ref = private_blob,
                            .data = try Pri.from_bytes(private_blob),
                        };
                    }
                }

                unreachable;
            }

            fn from(src: []const u8) Error!Self {
                return try proto.parse(Self, src);
            }

            pub inline fn from_bytes(src: []const u8) Error!Self {
                return try Self.from(src);
            }

            pub inline fn from_pem(pem: Pem) Error!Self {
                return try Self.from(pem.der);
            }
        };
    }

    pub const Rsa = private.PrivateKey(public.Rsa, struct {
        checksum: u64,
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

        const Self = @This();

        pub inline fn from_bytes(src: []const u8) Error!Self {
            return @This().from(src);
        }

        fn from(src: []const u8) Error!@This() {
            const key = try proto.parse(Self, src);

            if (!private.check_checksum(key.checksum)) return error.InvalidChecksum;

            return key;
        }
    });

    pub const Ecdsa = private.PrivateKey(public.Ecdsa, struct {
        checksum: u64,
        kind: []const u8,
        // Public parts
        nonce: []const u8,
        curve: []const u8,
        // Private parts
        sk: []const u8,
        comment: []const u8,
        _pad: proto.Padding,

        const Self = @This();

        pub inline fn from_bytes(src: []const u8) Error!Self {
            return @This().from(src);
        }

        fn from(src: []const u8) Error!Self {
            const key = try proto.parse(Self, src);

            if (!private.check_checksum(key.checksum)) return error.InvalidChecksum;

            return key;
        }
    });

    pub const Ed25519 = private.PrivateKey(public.Ed25519, struct {
        checksum: u64,
        kind: []const u8,
        // Public parts
        pk: []const u8,
        // Private parts
        sk: []const u8,
        comment: []const u8,
        _pad: proto.Padding,

        const Self = @This();

        pub inline fn from_bytes(src: []const u8) Error!Self {
            return @This().from(src);
        }

        fn from(src: []const u8) Error!Self {
            const key = try proto.parse(Self, src);

            if (!private.check_checksum(key.checksum)) return error.InvalidChecksum;

            return key;
        }
    });
};
