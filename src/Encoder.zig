const std = @import("std");
const ImFineAssembler = @import("Assembler.zig");

const io = std.io;
const debugPrint = std.debug.print;
const pow = std.math.pow;
const shr = std.math.shr;
const ArrayList = std.ArrayList;
const mem = std.mem;
const eql = mem.eql;
const builtin = std.builtin;
const ByteWidth: type = u32;
const SignedByteWidth: type = @Type(.{ .int = .{
    .bits = @typeInfo(ByteWidth).int.bits,
    .signedness = builtin.Signedness.signed,
} });
const Code = ImFineAssembler.Code;
const LabelSlot = ImFineAssembler.LabelSlot;
const SyntaxError = ImFineAssembler.SyntaxError;

allocator: mem.Allocator,
label_addr: *ArrayList(ImFineAssembler.Label2addr),
codes: *ArrayList(ImFineAssembler.Code),
out_buf: *ArrayList(u8),

const Encoder: type = @This();

const LABEL: u8 = 0b11 << 6;

pub fn init(assembler: *ImFineAssembler) Encoder {
    return Encoder{
        .allocator = assembler.allocator,
        .label_addr = &assembler.label_addr,
        .codes = &assembler.codes,
        .out_buf = &assembler.out_buf,
    };
}

fn toLSB(num: u128, index: usize) u8 {
    const mask: u32 = 0xff;
    const ofs: u5 = @intCast(index);
    const byte = shr(u128, num, ofs * 8) & mask;
    return @as(u8, @intCast(byte));
}

fn writeAddr(
    self: *Encoder,
    slot_place: ByteWidth,
    value: ByteWidth,
) void {
    const mask: ByteWidth = 0xff;
    const src_bytes = @sizeOf(ByteWidth);

    for (0..src_bytes) |i| {
        const ref = i + @as(ByteWidth, @intCast(slot_place));
        const ofs: u5 = @intCast(i);
        const byte = shr(ByteWidth, value, ofs * 8) & mask;
        self.out_buf.items[ref] = @as(u8, @intCast(byte));
    }
}

fn resolveLabelAddr(
    self: *Encoder,
    idx: u128,
    addr: usize,
) void {
    // addr means jump destination
    self.label_addr.items[@intCast(idx)].addr_abs = @intCast(addr);
}

fn getRelative(orig: ByteWidth, dst: ByteWidth) ByteWidth {
    const signed_orig: SignedByteWidth = @intCast(orig);
    const sined_dst: SignedByteWidth = @intCast(dst);
    const rel_addr: ByteWidth = @bitCast(sined_dst - signed_orig);
    return rel_addr;
}

fn resolveLabelSlots(
    self: *Encoder,
    label_slots: ArrayList(LabelSlot),
) !void {
    for (label_slots.items) |slot| {
        const label_idx = slot.label_idx;

        search_label: for (self.label_addr.items) |label| {
            if (label.label_idx == label_idx) {
                const slot_place = slot.place;

                const next_ins_addr = slot_place + @sizeOf(ByteWidth);
                const dst_addr = label.addr_abs;

                // next_ins_addr: origin; where the ip points
                // label_addr: destination
                const rel_addr = getRelative(next_ins_addr, dst_addr);

                self.writeAddr(slot_place, rel_addr);

                break :search_label;
            }
        } else return SyntaxError.LabelNotFound;
    }
}

fn getSecondOprandBytes(len: u3) u8 {
    return if (len == 0) 1 else @divExact(pow(u8, 2, len + 2), 8);
}

fn getOpcodeExt(code: *Code) u8 {
    return code.opcode << 2 | code.ext;
}

fn getLenReg(code: *Code) u8 {
    return @as(u8, @intCast(code.len)) << 5 | code.first_oprand << 2 | code.padding;
}

fn writeByteCodeToBuf(buf: []u8, code: *Code) u8 {
    var index: u8 = 0;
    const bytes: u8 = getSecondOprandBytes(code.len);

    buf[0] = getOpcodeExt(code);
    buf[1] = getLenReg(code);
    index += 2;

    for (0..bytes) |i| {
        const byte = toLSB(code.second_oprand, i);
        buf[2 + i] = byte;
        index += 1;
    }

    return index;
}

pub fn encode(
    self: *Encoder,
) !void {
    var buf: [0x50]u8 = undefined;
    var binary_idx: usize = 0;
    var label_slots = ArrayList(LabelSlot).init(self.allocator);
    defer label_slots.deinit();

    // iterate each line
    for (self.codes.items) |*code| {
        var index: u8 = 0;
        defer binary_idx += index;

        // when label itself
        if (code.opcode == LABEL) {
            // code.second_oprand == label_idx
            // binary_idx == where the label is
            self.resolveLabelAddr(code.second_oprand, binary_idx);
            continue;
        }

        // if opcode is a label slot; jmp <slot>
        if (code.opcode & LABEL == LABEL) {
            try label_slots.append(LabelSlot{
                .place = @intCast(binary_idx + 2),
                .label_idx = @intCast(code.second_oprand),
            });
            code.len = ImFineAssembler.getLen(1 << (@sizeOf(ByteWidth) * 8 - 1));
        }

        index += writeByteCodeToBuf(&buf, code);

        try self.out_buf.appendSlice(buf[0..index]);
    }
    try self.resolveLabelSlots(label_slots);
}
