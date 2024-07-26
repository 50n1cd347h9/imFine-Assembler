const std = @import("std");
const io = std.io;
const fs = std.fs;
const fmt = std.fmt;
const debugPrint = std.debug.print;
const stdin = io.getStdIn().reader();
const stdout = io.getStdOut().writer();
const process = std.process;
const print = std.debug.print;
const pow = std.math.pow;
const shr = std.math.shr;
const ArrayList = std.ArrayList;
const mem = std.mem;
const eql = mem.eql;
const copyForwards = mem.copyForwards;
const builtin = std.builtin;
const zig = std.zig;
const ByteWidth: type = u32;
const SignedByteWidth: type = @Type(.{ .Int = .{
    .bits = @typeInfo(ByteWidth).Int.bits,
    .signedness = builtin.Signedness.signed,
} });
const ImFineAssembler = @This();

allocator: mem.Allocator,
src_name: []u8,
dst_name: []u8,
line_buffer: [0x100]u8,
label_addr: ArrayList(Label2addr),
src_file_buf: [:0]u8,
out_buf: ArrayList(u8),
label_idx: ByteWidth,

fn toLSB(num: u128, index: usize) u8 {
    const mask: u32 = 0xff;
    const ofs: u5 = @intCast(index);
    const byte = shr(u128, num, ofs * 8) & mask;
    return @as(u8, @intCast(byte));
}

fn isLetterOrDigit(char: u8) bool {
    switch (char) {
        'a'...'z', 'A'...'Z', '0'...'9' => return true,
        else => return false,
    }
}

fn toInt(buf: []const u8) u128 {
    var res: u128 = 0;
    if (buf.len > 2 and buf[0] == '0' and buf[1] == 'x') {
        res = fmt.parseInt(u128, buf[2..buf.len], 16) catch 0;
    } else {
        res = fmt.parseInt(u128, buf, 10) catch 0;
    }
    return res;
}

fn nextChar(buf: []u8) ?u8 {
    const char = if (buf.len > 2) buf[1] else null;
    return char;
}

const COMMA: u8 = ',';
const SEMICOLON: u8 = ';';
const SPACE: u8 = ' ';
const SQUARE_BRACKET_OPEN = '[';
const SQUARE_BRACKET_CLOSE = ']';
const INDENT = '\t';
const COLON: u8 = ':';
const EOL = '\x00';
const LABEL: u8 = 0b11 << 6;
const TOKEN_DELIMITER = '\x00';
const LINE_DELIMITER = '\n';
const filename_len = 0x50;

var DEBUG = false;

var labels_buf: [0x1000]u8 = undefined;
var labels_buf_idx: usize = 0;
var file_name_buf = [_]u8{0} ** (filename_len * 2);

// the order is matter
// ldr, ldm
const instructions = [_][]const u8{
    "push",
    "pop",
    "add",
    "sub",
    "mul",
    "div",
    "and",
    "or",
    "xor",
    "shl",
    "ld",
    "ld",
    "cmp",
    "jmp",
    "jg",
    "jz",
    "jl",
    "call",
    "ret",
    "nop",
};
const registers = [_][]const u8{
    "ip",
    "sp",
    "fp",
    "flag",
    "gr0",
    "gr1",
};

const SyntaxError = error{
    CommaNeeded,
    OpenSquareBracketNeeded,
    CloseSquareBracketNeeded,
    LabelNotFound,
    UnknownToken,
};

const ArgError = error{
    FileNotFound,
    TooFewArgs,
};
const Token = enum {
    Register,
    Opcode,
    Imm,
    Ref,
    Label,
    InvalidToken,
};
const StrBc = struct {
    name: []const u8,
    bc: u8,
};
const Code = struct {
    opcode: u8,
    ext: u2,
    len: u3,
    first_oprand: u8,
    padding: u2,
    second_oprand: u128,
};

const Label2addr = struct {
    label_str: []u8,
    label_idx: ByteWidth,
    addr_abs: ByteWidth,
};

const LabelSlot = struct {
    place: ByteWidth,
    label_idx: ByteWidth,
};

const Int = struct {
    number: u128,
    len: u16,
};

pub fn init(allocator: mem.Allocator) ImFineAssembler {
    @memset(&file_name_buf, 0);

    return ImFineAssembler{
        .allocator = allocator,
        .src_name = undefined,
        .dst_name = undefined,
        .line_buffer = undefined,
        .label_addr = undefined,
        .src_file_buf = undefined,
        .out_buf = undefined,
        .label_idx = 0,
    };
}

fn strBCMap() type {
    return struct {
        var str_BC_map: [instructions.len + registers.len]StrBc = undefined;

        fn init() []StrBc {
            for (instructions, 0..) |instruction, i| {
                str_BC_map[i].name = instruction;
                str_BC_map[i].bc = @as(u8, @intCast(i));
            }
            for (registers, 0..) |register, i| {
                str_BC_map[instructions.len + i].name = register;
                str_BC_map[instructions.len + i].bc = @as(u8, @intCast(i));
            }
            return &str_BC_map;
        }
    };
}

// *const [][:0]u8 = pointer to an array of zero terminated const u8 values
pub fn parseArgs(self: *ImFineAssembler, args_p: *const [][:0]u8) !void {
    if (args_p.len < 2)
        return ArgError.TooFewArgs;

    for (args_p.*, 0..) |arg, i| {
        if (i == 0) continue;
        if (eql(u8, arg, "--debug")) {
            DEBUG = true;
            continue;
        }
        // arg is file name
        copyForwards(u8, &file_name_buf, arg);
    }
    self.asignOutputName();
}

fn asignOutputName(self: *ImFineAssembler) void {
    const extension = [4:0]u8{ '.', 'b', 'i', 'n' };

    const src_len = for (0..file_name_buf.len) |i| {
        if (file_name_buf[i] == EOL) {
            break @as(u8, @intCast(i));
        }
    } else @as(u8, @intCast(file_name_buf.len));

    self.src_name = file_name_buf[0..src_len];

    const dst_len = for (0..src_len) |i| {
        if (file_name_buf[i] == '.') {
            break @as(u8, @intCast(i + extension.len));
        }
        file_name_buf[src_len + i] = self.src_name[i];
    } else @as(u8, @intCast(src_len + extension.len));

    for (extension, 0..) |char, j| {
        file_name_buf[src_len + dst_len - extension.len + j] = char;
    }

    self.dst_name = file_name_buf[src_len .. src_len + dst_len];
}

fn emptyCode() Code {
    return Code{
        .opcode = 0,
        .ext = 0,
        .len = 0,
        .first_oprand = 0,
        .padding = 0,
        .second_oprand = 0,
    };
}

fn getBc(bcmap: []StrBc, name: []const u8) u8 {
    for (0..bcmap.len) |i| {
        if (eql(u8, bcmap[i].name, name))
            return bcmap[i].bc;
    }
    return 0;
}

fn getLabelIdx(self: *ImFineAssembler, label: []const u8) ?u128 {
    for (self.label_addr.items) |label_addr|
        if (eql(u8, label_addr.label_str, label))
            return label_addr.label_idx;
    return null;
}

fn isRegister(buf: []const u8) bool {
    for (registers) |register|
        if (eql(u8, buf, register))
            return true;
    return false;
}

fn isOpcode(buf: []const u8) bool {
    for (instructions) |instruction|
        if (eql(u8, buf, instruction))
            return true;
    return false;
}

fn isImm(buf: []const u8) bool {
    var res: ?u128 = 0;
    for ([2]u8{ 10, 16 }) |base| {
        if (buf.len > 2 and
            buf[0] == '0' and
            buf[1] == 'x')
        {
            res = std.fmt.parseInt(u128, buf[2..buf.len], base) catch null;
        } else res = std.fmt.parseInt(u128, buf, base) catch null;
        if (base == 16) {
            if (res == null) {
                return false;
            } else return true;
        }
    }
    return false;
}

fn isRef(buf: []const u8) bool {
    if (buf[0] == SQUARE_BRACKET_OPEN)
        return true;
    return false;
}

fn isLabel(buf: []const u8) bool {
    if (buf[buf.len - 1] == COLON)
        return true;
    return false;
}

fn getTokenType(buf: []const u8) Token {
    if (isOpcode(buf)) {
        return Token.Opcode;
    } else if (isImm(buf)) {
        return Token.Imm;
    } else if (isRegister(buf)) {
        return Token.Register;
    } else if (isRef(buf)) {
        return Token.Ref;
    } else if (isLabel(buf)) {
        return Token.Label;
    } else {
        return Token.InvalidToken;
    }
}

fn submitLabel(self: *ImFineAssembler, label: []u8) !void {
    const label_len = label.len;
    defer {
        labels_buf_idx += label_len;
        self.label_idx += 1;
    }

    const label_slice = labels_buf[labels_buf_idx .. labels_buf_idx + label_len];
    copyForwards(u8, label_slice, label);

    try self.label_addr.append(Label2addr{
        .label_idx = self.label_idx,
        .label_str = label_slice,
        .addr_abs = undefined,
    });
}

fn getLen(num: u128) u3 {
    return switch (num) {
        0 => 0b000,
        1...(pow(u16, 2, 8) - 1) => 0b001,
        pow(u16, 2, 8)...(pow(u32, 2, 16) - 1) => 0b010,
        pow(u32, 2, 16)...(pow(u64, 2, 32) - 1) => 0b011,
        pow(u64, 2, 32)...(pow(u128, 2, 64) - 1) => 0b100,
        pow(u128, 2, 64)...(pow(u129, 2, 128) - 1) => 0b100,
    };
}

fn resoluteLabelAddr(self: *ImFineAssembler, idx: u128, addr: usize) void {
    self.label_addr.items[@intCast(idx)].addr_abs = @intCast(addr);
}

fn getLabelAddr(self: *ImFineAssembler, idx: u128) ByteWidth {
    return self.label_addr.items[@intCast(idx)].addr_abs;
}

fn getRelative(orig: ByteWidth, dst: ByteWidth) ByteWidth {
    const signed_orig: SignedByteWidth = @intCast(orig);
    const sined_dst: SignedByteWidth = @intCast(dst);
    const rel_addr: ByteWidth = @bitCast(sined_dst - signed_orig);
    return rel_addr;
}

fn writeAddr(self: *ImFineAssembler, slot_place: ByteWidth, value: ByteWidth) void {
    const mask: ByteWidth = 0xff;
    const src_bytes = @sizeOf(ByteWidth);
    for (0..src_bytes) |i| {
        const ref = i + @as(ByteWidth, @intCast(slot_place));
        const ofs: u5 = @intCast(i);
        const byte = shr(ByteWidth, value, ofs * 8) & mask;
        self.out_buf.items[ref] = @as(u8, @intCast(byte));
    }
}

fn resoluteLabelSlots(self: *ImFineAssembler, label_slots: ArrayList(LabelSlot)) !void {
    for (label_slots.items) |slot| {
        const label_idx = slot.label_idx;
        search_label: for (self.label_addr.items) |label| {
            if (label.label_idx == label_idx) {
                const label_addr = label.addr_abs;
                const slot_place = slot.place;
                const next_ins_addr = slot_place + @sizeOf(ByteWidth);
                const rel_addr = getRelative(next_ins_addr, label_addr);
                self.writeAddr(slot_place, rel_addr);
                break :search_label;
            }
        } else return SyntaxError.LabelNotFound;
    }
}

fn getSecondOprandBytes(len: u3) u8 {
    return if (len == 0) 1 else @divExact(pow(u8, 2, len + 2), 8);
}

fn processLineTokens(self: *ImFineAssembler, str_BC_map: anytype, tokens: [3][]u8, tokens_sum: u32) !Code {
    const BC_imm: u2 = 0b00;
    const BC_reg: u2 = 0b01;
    const BC_imm_ref: u2 = 0b10;
    const BC_reg_ref: u2 = 0b11;
    var curr_line_code: Code = emptyCode();
    var curr_token_type: Token = undefined;
    var prev_token_type: Token = undefined;

    for (0..tokens_sum) |i| {
        defer prev_token_type = curr_token_type;
        const token = tokens[i];
        curr_token_type = getTokenType(token);

        switch (curr_token_type) {
            Token.Opcode => curr_line_code.opcode = getBc(str_BC_map, token),
            Token.Register => {
                if (tokens_sum != 3) {
                    curr_line_code.second_oprand = getBc(str_BC_map, token);
                    curr_line_code.ext = BC_reg;
                    continue;
                }
                curr_line_code.first_oprand = getBc(str_BC_map, token);
            },
            Token.Imm => {
                const int_num = toInt(token);
                curr_line_code.second_oprand = int_num;
                curr_line_code.ext = BC_imm;
            },
            // [], ref
            Token.Ref => {
                const inner = token[1 .. token.len - 1];
                curr_token_type = getTokenType(inner);
                if (curr_token_type == Token.Register) {
                    // ld
                    if (prev_token_type == Token.Opcode) {
                        curr_line_code.opcode += 1;
                        curr_line_code.first_oprand = getBc(str_BC_map, inner);
                        continue;
                    }
                    curr_line_code.second_oprand = getBc(str_BC_map, inner);
                    curr_line_code.ext = BC_reg_ref;
                    continue;
                }
                //imm
                const int_num = toInt(inner);
                curr_line_code.second_oprand = int_num;
                curr_line_code.ext = BC_imm_ref;
            },
            Token.Label => {
                const label = token[0 .. token.len - 1];
                curr_line_code.opcode = LABEL;
                // if already submitted
                if (self.getLabelIdx(label)) |idx| {
                    curr_line_code.second_oprand = idx;
                    continue;
                }
                curr_line_code.second_oprand = self.label_idx;
                try self.submitLabel(label);
            },
            Token.InvalidToken => {
                if (prev_token_type == Token.Opcode) {
                    curr_line_code.opcode |= LABEL;
                    if (self.getLabelIdx(token)) |idx| {
                        curr_line_code.second_oprand = idx;
                        continue;
                    }
                    curr_line_code.second_oprand = self.label_idx;
                    try self.submitLabel(token);
                    continue;
                }
                return SyntaxError.UnknownToken;
            },
        }
    }
    curr_line_code.len = getLen(curr_line_code.second_oprand);
    return curr_line_code;
}

fn parse(self: *ImFineAssembler, tokens: *ArrayList(?[]u8), codes: *ArrayList(Code)) !void {
    const str_BC_map = strBCMap().init();
    var curr_line_tokens: [3][]u8 = undefined;
    var idx: usize = 0;

    for (tokens.items) |token| {
        if (token == null) {
            defer idx = 0;
            const tokens_sum: u32 = @intCast(idx);
            const code: Code = try processLineTokens(
                self,
                str_BC_map,
                curr_line_tokens,
                tokens_sum,
            );
            try codes.append(code);
            continue;
        }
        curr_line_tokens[idx] = token.?;
        idx += 1;
    }
}

fn nextToken(line: []u8, begin: *u32, curr: *u32) !?[]u8 {
    var begin_idx = begin.*;
    var curr_idx = curr.*;
    defer {
        begin.* = begin_idx;
        curr.* = curr_idx;
    }
    const buf_end = line.len;
    var token_str: ?[]u8 = null;

    while (begin_idx < buf_end) : (curr_idx += 1) {
        defer begin_idx = curr_idx;
        const char = line[begin_idx];
        switch (char) {
            SEMICOLON, EOL => break,
            SQUARE_BRACKET_CLOSE => return SyntaxError.OpenSquareBracketNeeded,
            SPACE, INDENT, COMMA => continue,
            SQUARE_BRACKET_OPEN => {
                while (nextChar(line[curr_idx..buf_end])) |next| {
                    curr_idx += 1;
                    if (next == SQUARE_BRACKET_CLOSE) {
                        curr_idx += 1;
                        break;
                    }
                } else return SyntaxError.CloseSquareBracketNeeded;
                token_str = line[begin_idx..curr_idx];
                break;
            },
            else => {
                while (nextChar(line[curr_idx..buf_end])) |next| {
                    defer curr_idx += 1;
                    if (isLetterOrDigit(next))
                        continue;
                    switch (next) {
                        SQUARE_BRACKET_CLOSE => return SyntaxError.OpenSquareBracketNeeded,
                        COLON => {
                            curr_idx += 2;
                            break;
                        },
                        else => break,
                    }
                } else curr_idx = @intCast(buf_end);
                token_str = line[begin_idx..curr_idx];
                break;
            },
        }
    }

    return token_str;
}

fn toBinary(self: *ImFineAssembler, codes: *ArrayList(Code)) !void {
    var buf: [0x50]u8 = undefined;
    var binary_idx: usize = 0;
    var label_slots = ArrayList(LabelSlot).init(self.allocator);
    defer label_slots.deinit();

    // iterate each line
    for (codes.items) |*code| {
        var index: u8 = 0;
        defer binary_idx += index;

        if (code.opcode == LABEL) {
            self.resoluteLabelAddr(code.second_oprand, binary_idx);
            continue;
        }
        // if opcode is a label slot
        if (code.opcode & LABEL == LABEL) {
            try label_slots.append(LabelSlot{
                .place = @intCast(binary_idx + 2),
                .label_idx = @intCast(code.second_oprand),
            });
            code.len = getLen(1 << (@sizeOf(ByteWidth) * 8 - 1));
        }

        const bytes: u8 = getSecondOprandBytes(code.len);
        index = 2;
        buf[0] = code.opcode << 2 | code.ext;
        buf[1] = @as(u8, @intCast(code.len)) << 5 | code.first_oprand << 2 | code.padding;
        for (0..bytes) |i| {
            const byte = toLSB(code.second_oprand, i);
            buf[2 + i] = byte;
            index += 1;
        }
        try self.out_buf.appendSlice(buf[0..index]);
    }
    try self.resoluteLabelSlots(label_slots);
}

var src_buf_idx: usize = 0;
fn nextLine(src_buf: anytype) ?[]u8 {
    const start = src_buf_idx;
    const line = for (src_buf[start..src_buf.len]) |char| {
        src_buf_idx += 1;
        if (char == LINE_DELIMITER)
            break src_buf[start..src_buf_idx];
    } else src_buf[start..src_buf.len];

    return if (line.len == 1 and line[0] == LINE_DELIMITER)
        nextLine(src_buf)
    else if (line.len == 0)
        null
    else
        line[0 .. line.len - 1];
}

fn tokenize(
    self: *ImFineAssembler,
    tokens: *ArrayList(?[]u8),
) !void {
    while (nextLine(self.src_file_buf)) |line| {
        var begin_idx: u32 = 0;
        var curr_idx: u32 = 0;
        while (try nextToken(line, &begin_idx, &curr_idx)) |token|
            try tokens.append(token);
        try tokens.append(null);
    }
}

fn assemble(self: *ImFineAssembler) !void {
    const src_file = try fs.cwd().openFile(self.src_name, .{ .mode = .read_only });
    self.src_file_buf = try zig.readSourceFileToEndAlloc(self.allocator, src_file, null);
    defer self.allocator.free(self.src_file_buf);
    src_file.close();

    const dst_file = try fs.cwd().createFile(self.dst_name, .{});
    defer dst_file.close();
    const output_writer = dst_file.writer();

    var tokens = ArrayList(?[]u8).init(self.allocator);
    defer tokens.deinit();
    var codes = ArrayList(Code).init(self.allocator);
    defer codes.deinit();
    self.label_addr = ArrayList(Label2addr).init(self.allocator);
    defer self.label_addr.deinit();
    self.out_buf = ArrayList(u8).init(self.allocator);
    defer self.out_buf.deinit();

    try self.tokenize(&tokens);
    try self.parse(&tokens, &codes);
    try self.toBinary(&codes);
    try output_writer.writeAll(self.out_buf.items);
}

pub fn entry(self: *ImFineAssembler) void {
    self.assemble() catch |err| {
        print("{!}\n", .{err});
        fs.cwd().deleteFile(
            self.dst_name,
        ) catch return;
    };
}
