const std = @import("std");
const constants = @import("../../src/protocol/constants.zig");
const obfuscation = @import("../../src/protocol/obfuscation.zig");
const crypto = @import("../../src/crypto/crypto.zig");

fn usage() noreturn {
    std.debug.print("usage: obf_handshake_gen <secret_hex32> <dc_idx> [abridged|intermediate|secure]\n", .{});
    std.process.exit(2);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // argv0

    const secret_hex = args.next() orelse usage();
    if (secret_hex.len != 32) usage();
    const dc_idx_str = args.next() orelse usage();
    const proto_str = args.next() orelse "intermediate";

    const dc_idx = std.fmt.parseInt(i16, dc_idx_str, 10) catch usage();
    if (dc_idx == 0) usage();

    const proto_tag: constants.ProtoTag = if (std.mem.eql(u8, proto_str, "abridged"))
        .abridged
    else if (std.mem.eql(u8, proto_str, "intermediate"))
        .intermediate
    else if (std.mem.eql(u8, proto_str, "secure"))
        .secure
    else
        usage();

    var secret: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&secret, secret_hex) catch usage();

    var plain = obfuscation.generateNonce();
    const tag_bytes = proto_tag.toBytes();
    @memcpy(plain[constants.proto_tag_pos..][0..4], &tag_bytes);
    std.mem.writeInt(i16, plain[constants.dc_idx_pos..][0..2], dc_idx, .little);

    const prekey = plain[constants.skip_len .. constants.skip_len + constants.prekey_len];
    const iv_bytes = plain[constants.skip_len + constants.prekey_len .. constants.skip_len + constants.prekey_len + constants.iv_len];
    const iv = std.mem.readInt(u128, iv_bytes, .big);

    var key_input: [constants.prekey_len + 16]u8 = undefined;
    @memcpy(key_input[0..constants.prekey_len], prekey);
    @memcpy(key_input[constants.prekey_len..], &secret);
    const key = crypto.sha256(&key_input);

    var enc = crypto.AesCtr.init(&key, iv);
    defer enc.wipe();
    var encrypted = plain;
    enc.apply(&encrypted);

    var stdout = std.fs.File.stdout().writer(&.{});
    var out_buf: [constants.handshake_len * 2 + 1]u8 = undefined;
    _ = std.fmt.bytesToHex(out_buf[0 .. constants.handshake_len * 2], &encrypted, .lower);
    try stdout.interface.writeAll(out_buf[0 .. constants.handshake_len * 2]);
    try stdout.interface.writeAll("\n");
}
