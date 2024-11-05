//! SSH Keys and Certificates parsing and manipulation utilities.

const std = @import("std");

pub const cert = @import("cert.zig");
pub const key = @import("key.zig");

// TODO: Map errors
pub const Error = error{
    InvalidFileFormat,
} || std.base64.Error || std.mem.Allocator.Error;

// TODO: AutoDecoder

/// Decode T from PEM to DER.
///
/// TODO: Memory is owned by Der, with refrences to the original data which
/// **SHOULD** outlive Der.
pub fn GenericDecoder(comptime T: type, comptime D: type) type {
    if (@typeInfo(T) != .@"struct")
        @compileError("Expected struct");

    if (!@hasDecl(T, "tokenize"))
        @compileError("Must define tokenize");

    return struct {
        allocator: std.mem.Allocator,
        decoder: D,

        const Self = @This();

        /// Unmanaged data with references to data that *SHOULD* outlive it.
        fn Unmanaged(comptime U: type) type {
            return struct {
                data: U,
            };
        }

        /// Managed data with owned memory.
        fn Managed(comptime U: type) type {
            return struct {
                allocator: std.mem.Allocator,
                data: U,

                pub fn deinit(self: *const @This()) void {
                    self.allocator.free(self.data.der);
                }
            };
        }

        /// Decode T from PEM to DER. This is done in-place, without allocating
        /// memory, changing the reference data. Referenced data must outlive
        /// this.
        pub fn decode_in_place(decoder: std.base64.Base64Decoder, src: []u8) !Unmanaged(T) {
            var ret: Self.Unmanaged(T) = .{
                .data = try Self.parse_fields(src),
            };

            // TODO: Decode in place with Base64DecoderWithIgnore.
            const len = try decoder.calcSizeForSlice(ret.data.der);

            try decoder.decode(ret.data.der[0..len], ret.data.der);

            ret.data.der.len = len;

            return ret;
        }

        pub fn init(allocator: std.mem.Allocator, decoder: D) Self {
            return .{
                .allocator = allocator,
                .decoder = decoder,
            };
        }

        fn parse_fields(src: []const u8) !T {
            var it = T.tokenize(src);

            var ret: T = undefined;

            inline for (comptime std.meta.fields(T)) |field| {
                const val = it.next() orelse
                    return error.InvalidFileFormat;

                if (@typeInfo(field.type) == .@"struct" and @hasDecl(field.type, "parse")) {
                    try field.type.parse(val);

                    continue;
                }

                @field(ret, field.name) = switch (field.type) {
                    []u8 => @constCast(val),
                    []const u8 => val,
                    else => @panic("Wrong type"),
                };
            }

            return ret;
        }

        inline fn decode_with_true_size(self: *const Self, data: *const T) ![]u8 {
            const len = try self.decoder.calcSizeForSlice(data.der);

            const der = try self.allocator.alloc(u8, len);
            errdefer self.allocator.free(der);

            try self.decoder.decode(der, data.der);

            return der;
        }

        inline fn decode_with_total_size(self: *const Self, data: *const T) ![]u8 {
            const len = try self.decoder.calcSizeUpperBound(data.der.len);

            const der = try self.allocator.alloc(u8, len);
            defer self.allocator.free(der);

            const acc_len = try self.decoder.decode(der, data.der);

            const aux = try self.allocator.alloc(u8, acc_len);
            errdefer self.allocator.free(aux);

            std.mem.copyForwards(u8, aux, der[0..acc_len]);

            return aux;
        }

        pub fn decode(self: *const Self, src: []const u8) !Managed(T) {
            var ret: Self.Managed(T) = .{
                .allocator = self.allocator,
                .data = try Self.parse_fields(src),
            };

            // Since Zig's `Base64DecoderWithIgnore` does not support `calcSizeForSlice`
            // we need to alloc twice in order to get the actual decoded size.
            ret.data.der = if (@hasDecl(D, "calcSizeForSlice"))
                try self.decode_with_true_size(&ret.data)
            else
                try self.decode_with_total_size(&ret.data);

            return ret;
        }
    };
}

pub const pem = struct {
    pub const PublicKeyDecoder = GenericDecoder(key.public.Pem, std.base64.Base64Decoder);
    pub const PrivateKeyDecoder = GenericDecoder(key.private.Pem, std.base64.Base64DecoderWithIgnore);
    pub const CertificateDecoder = GenericDecoder(cert.Pem, std.base64.Base64Decoder);
};

pub const base64 = struct {
    pub const pem = struct {
        pub const Decoder = std.base64.Base64DecoderWithIgnore.init(
            std.base64.standard.alphabet_chars,
            std.base64.standard.pad_char,
            &.{ '\n', '\r' },
        );
    };
};
