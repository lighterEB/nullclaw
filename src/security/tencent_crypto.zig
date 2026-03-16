//! Tencent platform cryptographic primitives.
//!
//! Provides three focused utilities required for WeChat/WeChat Work and
//! Tencent Cloud (Hunyuan) integration:
//!
//!  - AES-256-CBC + PKCS#7  — WeChat enterprise message encryption (企业号消息加密方案)
//!  - wechatSha1Signature    — WeChat URL-verification signature (SHA-1 of sorted strings)
//!  - tc3Sign                — Tencent Cloud TC3-HMAC-SHA256 request signing (Hunyuan, etc.)
//!
//! All functions are allocation-free where the output size is statically known.
//! AES functions allocate because ciphertext/plaintext lengths are runtime values.

const std = @import("std");
const Aes256 = std.crypto.core.aes.Aes256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha1 = std.crypto.hash.Sha1;

/// AES block size in bytes.
pub const AES_BLOCK: usize = 16;

// ── PKCS#7 ──────────────────────────────────────────────────────────────────

/// Apply PKCS#7 padding so the result length is a multiple of 16.
/// Allocates; caller must free.
pub fn pkcs7Pad(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const pad_len: u8 = @intCast(AES_BLOCK - (data.len % AES_BLOCK));
    const out = try allocator.alloc(u8, data.len + pad_len);
    @memcpy(out[0..data.len], data);
    @memset(out[data.len..], pad_len);
    return out;
}

/// Validate and strip PKCS#7 padding. Returns a sub-slice of `data` (no allocation).
pub fn pkcs7Unpad(data: []const u8) ![]const u8 {
    if (data.len == 0 or data.len % AES_BLOCK != 0) return error.InvalidPadding;
    const pad_len = data[data.len - 1];
    if (pad_len == 0 or pad_len > AES_BLOCK) return error.InvalidPadding;
    for (data[data.len - pad_len ..]) |b| {
        if (b != pad_len) return error.InvalidPadding;
    }
    return data[0 .. data.len - pad_len];
}

// ── AES-256-CBC ──────────────────────────────────────────────────────────────

/// AES-256-CBC encrypt with PKCS#7 padding.
/// Returns heap-allocated ciphertext. Caller must free.
pub fn aesCbcEncrypt(
    allocator: std.mem.Allocator,
    key: [32]u8,
    iv: [16]u8,
    plaintext: []const u8,
) ![]u8 {
    const padded = try pkcs7Pad(allocator, plaintext);
    defer allocator.free(padded);

    const out = try allocator.alloc(u8, padded.len);
    const ctx = Aes256.initEnc(key);
    var prev: [AES_BLOCK]u8 = iv;

    var i: usize = 0;
    while (i < padded.len) : (i += AES_BLOCK) {
        var block: [AES_BLOCK]u8 = padded[i..][0..AES_BLOCK].*;
        for (&block, prev) |*b, p| b.* ^= p;
        ctx.encrypt(out[i..][0..AES_BLOCK], &block);
        prev = out[i..][0..AES_BLOCK].*;
    }
    return out;
}

/// AES-256-CBC decrypt with PKCS#7 unpadding.
/// Returns heap-allocated plaintext. Caller must free.
pub fn aesCbcDecrypt(
    allocator: std.mem.Allocator,
    key: [32]u8,
    iv: [16]u8,
    ciphertext: []const u8,
) ![]u8 {
    if (ciphertext.len == 0 or ciphertext.len % AES_BLOCK != 0)
        return error.InvalidCiphertext;

    var buf = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(buf);

    const ctx = Aes256.initDec(key);
    var prev: [AES_BLOCK]u8 = iv;

    var i: usize = 0;
    while (i < ciphertext.len) : (i += AES_BLOCK) {
        const block: [AES_BLOCK]u8 = ciphertext[i..][0..AES_BLOCK].*;
        ctx.decrypt(buf[i..][0..AES_BLOCK], &block);
        for (buf[i..][0..AES_BLOCK], prev) |*b, p| b.* ^= p;
        prev = block;
    }

    const unpadded = try pkcs7Unpad(buf);
    return try allocator.dupe(u8, unpadded);
}

// ── WeChat URL verification ──────────────────────────────────────────────────

/// WeChat URL-verification signature.
///
/// Algorithm: SHA-1(sort(token, timestamp, nonce)) — all three strings are
/// sorted lexicographically, concatenated without separator, then SHA-1 hashed.
///
/// Returns lowercase hex (40 chars) on the stack — no allocation.
pub fn wechatSha1Signature(
    token: []const u8,
    timestamp: []const u8,
    nonce: []const u8,
) [40]u8 {
    var strs = [3][]const u8{ token, timestamp, nonce };
    std.mem.sort([]const u8, &strs, {}, strLessThan);

    var h = Sha1.init(.{});
    for (strs) |s| h.update(s);
    var digest: [Sha1.digest_length]u8 = undefined;
    h.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

fn strLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// ── TC3-HMAC-SHA256 ──────────────────────────────────────────────────────────

/// Tencent Cloud TC3-HMAC-SHA256 signing algorithm.
///
/// Used by Hunyuan and other Tencent Cloud APIs. Identical structure to AWS SigV4:
///
///   SecretDate    = HMAC-SHA256("TC3" + secret_key, date)
///   SecretService = HMAC-SHA256(SecretDate, service)
///   SecretSigning = HMAC-SHA256(SecretService, "tc3_request")
///   Signature     = Hex(HMAC-SHA256(SecretSigning, string_to_sign))
///
/// Parameters:
///   secret_key     — bare Tencent Cloud SecretKey (max 220 bytes)
///   date           — UTC date "YYYY-MM-DD"
///   service        — Tencent Cloud service name, e.g. "hunyuan"
///   string_to_sign — pre-built canonical string (caller constructs per API spec)
///
/// Returns lowercase hex signature (64 chars) on the stack — no allocation.
pub fn tc3Sign(
    secret_key: []const u8,
    date: []const u8,
    service: []const u8,
    string_to_sign: []const u8,
) error{KeyTooLong}![64]u8 {
    // Build "TC3{secret_key}" in a stack buffer.
    var kbuf: [224]u8 = undefined;
    if (3 + secret_key.len > kbuf.len) return error.KeyTooLong;
    @memcpy(kbuf[0..3], "TC3");
    @memcpy(kbuf[3..][0..secret_key.len], secret_key);
    const tc3_key = kbuf[0 .. 3 + secret_key.len];

    var secret_date: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&secret_date, date, tc3_key);

    var secret_service: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&secret_service, service, &secret_date);

    var secret_signing: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&secret_signing, "tc3_request", &secret_service);

    var signature: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&signature, string_to_sign, &secret_signing);

    return std.fmt.bytesToHex(signature, .lower);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "pkcs7Pad adds correct padding" {
    // 3 bytes → pad to 16 (pad_len = 13 = 0x0D)
    const padded = try pkcs7Pad(std.testing.allocator, "abc");
    defer std.testing.allocator.free(padded);
    try std.testing.expectEqual(@as(usize, 16), padded.len);
    for (padded[3..]) |b| try std.testing.expectEqual(@as(u8, 13), b);
}

test "pkcs7Pad on block boundary adds full padding block" {
    // 16 bytes → pad to 32 (pad_len = 16 = 0x10)
    const padded = try pkcs7Pad(std.testing.allocator, "1234567890123456");
    defer std.testing.allocator.free(padded);
    try std.testing.expectEqual(@as(usize, 32), padded.len);
    for (padded[16..]) |b| try std.testing.expectEqual(@as(u8, 16), b);
}

test "pkcs7Unpad strips padding correctly" {
    // 3 bytes of data + 13 bytes of value 13 (correct PKCS#7 for a 16-byte block)
    var buf = [_]u8{ 'a', 'b', 'c' } ++ [_]u8{13} ** 13;
    const result = try pkcs7Unpad(&buf);
    try std.testing.expectEqualStrings("abc", result);
}

test "pkcs7Unpad rejects invalid padding byte" {
    // Last byte says pad_len=4, but third-from-last byte is 3 — mismatch → invalid.
    var buf = [_]u8{0} ** 11 ++ [_]u8{ 4, 4, 3, 4 };
    try std.testing.expectError(error.InvalidPadding, pkcs7Unpad(&buf));
}

test "pkcs7Unpad rejects zero padding byte" {
    var buf = [_]u8{'a'} ++ [_]u8{0} ** 15;
    try std.testing.expectError(error.InvalidPadding, pkcs7Unpad(&buf));
}

test "aesCbcEncrypt decrypt roundtrip" {
    const key = [_]u8{0x2b} ** 32;
    const iv = [_]u8{0x00} ** 16;
    const plaintext = "WeChat message body — hello 你好";

    const ct = try aesCbcEncrypt(std.testing.allocator, key, iv, plaintext);
    defer std.testing.allocator.free(ct);

    const pt = try aesCbcDecrypt(std.testing.allocator, key, iv, ct);
    defer std.testing.allocator.free(pt);

    try std.testing.expectEqualStrings(plaintext, pt);
}

test "aesCbcEncrypt output length is multiple of 16" {
    const key = [_]u8{0x01} ** 32;
    const iv = [_]u8{0x00} ** 16;

    const ct = try aesCbcEncrypt(std.testing.allocator, key, iv, "hello");
    defer std.testing.allocator.free(ct);

    try std.testing.expect(ct.len % AES_BLOCK == 0);
}

test "aesCbcEncrypt different IVs produce different ciphertext" {
    const key = [_]u8{0x42} ** 32;
    const iv1 = [_]u8{0x01} ** 16;
    const iv2 = [_]u8{0x02} ** 16;

    const ct1 = try aesCbcEncrypt(std.testing.allocator, key, iv1, "same plaintext");
    defer std.testing.allocator.free(ct1);
    const ct2 = try aesCbcEncrypt(std.testing.allocator, key, iv2, "same plaintext");
    defer std.testing.allocator.free(ct2);

    try std.testing.expect(!std.mem.eql(u8, ct1, ct2));
}

test "aesCbcDecrypt rejects non-block-aligned ciphertext" {
    const key = [_]u8{0x01} ** 32;
    const iv = [_]u8{0x00} ** 16;
    try std.testing.expectError(
        error.InvalidCiphertext,
        aesCbcDecrypt(std.testing.allocator, key, iv, "not aligned"),
    );
}

test "wechatSha1Signature is deterministic" {
    const s1 = wechatSha1Signature("mytoken", "1234567890", "abc123");
    const s2 = wechatSha1Signature("mytoken", "1234567890", "abc123");
    try std.testing.expectEqualSlices(u8, &s1, &s2);
}

test "wechatSha1Signature is order-independent" {
    // Permuting the three arguments must not change the result (sort normalises order).
    const s1 = wechatSha1Signature("token", "stamp", "nonce");
    const s2 = wechatSha1Signature("nonce", "token", "stamp");
    const s3 = wechatSha1Signature("stamp", "nonce", "token");
    try std.testing.expectEqualSlices(u8, &s1, &s2);
    try std.testing.expectEqualSlices(u8, &s1, &s3);
}

test "wechatSha1Signature changes when input changes" {
    const s1 = wechatSha1Signature("token", "1234567890", "nonce");
    const s2 = wechatSha1Signature("token", "9999999999", "nonce");
    try std.testing.expect(!std.mem.eql(u8, &s1, &s2));
}

test "wechatSha1Signature output is 40 hex chars" {
    const sig = wechatSha1Signature("t", "ts", "n");
    try std.testing.expectEqual(@as(usize, 40), sig.len);
    for (sig) |c| try std.testing.expect(
        (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'),
    );
}

test "tc3Sign is deterministic" {
    const s1 = try tc3Sign("mysecret", "2026-03-16", "hunyuan", "string_to_sign");
    const s2 = try tc3Sign("mysecret", "2026-03-16", "hunyuan", "string_to_sign");
    try std.testing.expectEqualSlices(u8, &s1, &s2);
}

test "tc3Sign changes with different secret key" {
    const s1 = try tc3Sign("key-a", "2026-03-16", "hunyuan", "payload");
    const s2 = try tc3Sign("key-b", "2026-03-16", "hunyuan", "payload");
    try std.testing.expect(!std.mem.eql(u8, &s1, &s2));
}

test "tc3Sign changes with different date" {
    const s1 = try tc3Sign("key", "2026-03-16", "hunyuan", "payload");
    const s2 = try tc3Sign("key", "2026-03-17", "hunyuan", "payload");
    try std.testing.expect(!std.mem.eql(u8, &s1, &s2));
}

test "tc3Sign changes with different service" {
    const s1 = try tc3Sign("key", "2026-03-16", "hunyuan", "payload");
    const s2 = try tc3Sign("key", "2026-03-16", "cos", "payload");
    try std.testing.expect(!std.mem.eql(u8, &s1, &s2));
}

test "tc3Sign output is 64 hex chars" {
    const sig = try tc3Sign("k", "2026-03-16", "hunyuan", "s");
    try std.testing.expectEqual(@as(usize, 64), sig.len);
    for (sig) |c| try std.testing.expect(
        (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'),
    );
}

test "tc3Sign key too long returns error" {
    const long_key = "x" ** 222;
    try std.testing.expectError(
        error.KeyTooLong,
        tc3Sign(long_key, "2026-03-16", "hunyuan", "payload"),
    );
}
