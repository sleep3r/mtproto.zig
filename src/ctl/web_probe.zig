//! End-to-end installer gate. TLS and WSS use Python's standard library; the
//! MTProxy probe uses Zig's AES implementation. No permanent secret leaves Zig.
const std = @import("std");
const sys = @import("sys.zig");
const Config = @import("proxy_config").Config;
const capability = @import("web_capability");

const Probe = struct {
    request: [108]u8,
    response_key: [512]u8,
};

fn activeSecret(cfg: *Config, seconds: i64) ?[16]u8 {
    var users = cfg.users.iterator();
    while (users.next()) |user| {
        if (cfg.user_expirations) |expirations| {
            if (expirations.get(user.key_ptr.*)) |expires| {
                if (seconds >= expires) continue;
            }
        }
        return user.value_ptr.*;
    }
    return null;
}

fn makeProbe(secret: [16]u8, initial: [64]u8, nonce: [16]u8, seconds: u64) Probe {
    var clear: [108]u8 = [_]u8{0} ** 108;
    @memcpy(clear[0..64], &initial);
    @memset(clear[56..60], 0xdd);
    std.mem.writeInt(i16, clear[60..62], 2, .little);
    std.mem.writeInt(u32, clear[64..68], 40, .little);
    std.mem.writeInt(u64, clear[76..84], seconds << 32, .little);
    std.mem.writeInt(u32, clear[84..88], 20, .little);
    std.mem.writeInt(u32, clear[88..92], 0xbe7e8ef1, .little);
    @memcpy(clear[92..108], &nonce);

    var material: [48]u8 = undefined;
    @memcpy(material[0..32], clear[8..40]);
    @memcpy(material[32..48], &secret);
    var encrypt_key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&material, &encrypt_key, .{});
    var reversed: [48]u8 = undefined;
    for (&reversed, 0..) |*byte, index| byte.* = clear[55 - index];
    @memcpy(material[0..32], reversed[0..32]);
    var decrypt_key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&material, &decrypt_key, .{});
    defer std.crypto.secureZero(u8, &material);
    defer std.crypto.secureZero(u8, &encrypt_key);
    defer std.crypto.secureZero(u8, &decrypt_key);

    var result: Probe = undefined;
    const encrypt = std.crypto.core.aes.Aes256.initEnc(encrypt_key);
    std.crypto.core.modes.ctr(@TypeOf(encrypt), encrypt, &result.request, &clear, clear[40..56].*, .big);
    @memcpy(result.request[0..56], clear[0..56]);
    const decrypt = std.crypto.core.aes.Aes256.initEnc(decrypt_key);
    const zeros = [_]u8{0} ** 512;
    std.crypto.core.modes.ctr(@TypeOf(decrypt), decrypt, &result.response_key, &zeros, reversed[32..48].*, .big);
    return result;
}

pub fn verify(allocator: std.mem.Allocator, domain: []const u8, config_path: []const u8) !bool {
    if (!sys.commandExists("python3")) return error.PythonUnavailable;
    var cfg = try Config.loadFromFile(allocator, config_path);
    defer cfg.deinit(allocator);
    const io = std.Io.Threaded.global_single_threaded.io();
    const seconds: i64 = @intCast(std.Io.Clock.real.now(io).toSeconds());
    const secret = activeSecret(&cfg, seconds) orelse return error.NoActiveUsers;
    const bridge_capability = capability.deriveForPaddedSecret(domain, secret);
    var initial: [64]u8 = undefined;
    io.random(&initial);
    // Keep the preamble outside the reserved HTTP/TLS/transport signatures.
    initial[0] = 0x55;
    initial[4] = 0x55;
    var nonce: [16]u8 = undefined;
    io.random(&nonce);
    var probe = makeProbe(secret, initial, nonce, @intCast(seconds));
    defer std.crypto.secureZero(u8, &probe.response_key);
    var input: std.Io.Writer.Allocating = .init(allocator);
    defer {
        std.crypto.secureZero(u8, input.written());
        input.deinit();
    }
    try std.json.Stringify.value(.{
        .domain = domain,
        .capability = &bridge_capability,
        .ws_path = cfg.web.effectiveWsPath(),
        .request = &std.fmt.bytesToHex(probe.request, .lower),
        .response_key = &std.fmt.bytesToHex(probe.response_key, .lower),
        .nonce = &std.fmt.bytesToHex(nonce, .lower),
    }, .{}, &input.writer);
    const result = try sys.execInput(allocator, &.{ "python3", "-c", @embedFile("web_probe.py") }, input.written());
    defer result.deinit();
    return result.exit_code == 0 and std.mem.eql(u8, std.mem.trim(u8, result.stdout, " \r\n"), "WEB_PROBE_OK");
}

test "installer req_pq wire bytes and response key match an independent AES vector" {
    var initial: [64]u8 = undefined;
    for (&initial, 1..) |*byte, index| byte.* = @intCast(index);
    var nonce: [16]u8 = undefined;
    for (&nonce, 0..) |*byte, index| byte.* = @intCast(index);
    const probe = makeProbe([_]u8{0x11} ** 16, initial, nonce, 1700000000);
    var expected: [108]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738fa994dc688e58644f6df46d7a17f438b1168566826f172a3bc770868794270d81b763e816ec6381ef8f6dd717296ca1b91149ee9");
    try std.testing.expectEqualSlices(u8, &expected, &probe.request);
    var expected_response: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_response, "7726db6e707a15c5ae6d2554e0b12fd729bef3d40840f58506daf8b14517554aa3d2bd4d597514940bf80d7c66ad5e15452ecba27b1bfa58164ff2ca83022692");
    try std.testing.expectEqualSlices(u8, &expected_response, probe.response_key[0..64]);
}

test "installer probe never chooses an expired user" {
    const allocator = std.testing.allocator;
    var cfg = try Config.parse(allocator,
        \\[access.users]
        \\expired = "11111111111111111111111111111111"
        \\[access.user_expirations]
        \\expired = "2020-01-01"
    );
    defer cfg.deinit(allocator);
    try std.testing.expect(activeSecret(&cfg, 1700000000) == null);
    const name = try allocator.dupe(u8, "active");
    try cfg.users.put(name, [_]u8{0x22} ** 16);
    try std.testing.expectEqual([_]u8{0x22} ** 16, activeSecret(&cfg, 1700000000).?);
}
