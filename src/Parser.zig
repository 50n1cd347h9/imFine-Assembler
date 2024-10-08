const std = @import("std");
const ArrayList = std.ArrayList;
const ImFineAssembler = @import("Assembler.zig");

const mem = std.mem;
const eql = mem.eql;
const copyForwards = mem.copyForwards;
const fmt = std.fmt;
const SyntaxError = ImFineAssembler.SyntaxError;
const Code: type = ImFineAssembler.Code;

tokens: *ArrayList(?[]u8),
codes: *ArrayList(Code),
label_addr: *ArrayList(ImFineAssembler.Label2addr),
label_idx: ImFineAssembler.ByteWidth,

const Parser = @This();

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

const StrBc = struct {
    name: []const u8,
    bc: u8,
};

const Token = enum {
    Register,
    Opcode,
    Imm,
    Ref,
    Label,
    InvalidToken,
};

pub fn init(assembler: *ImFineAssembler) Parser {
    return Parser{
        .tokens = &assembler.tokens,
        .codes = &assembler.codes,
        .label_addr = &assembler.label_addr,
        .label_idx = 0,
    };
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

fn toInt(buf: []const u8) u128 {
    var res: u128 = 0;
    if (buf.len > 2 and buf[0] == '0' and buf[1] == 'x') {
        res = fmt.parseInt(u128, buf[2..buf.len], 16) catch 0;
    } else {
        res = fmt.parseInt(u128, buf, 10) catch 0;
    }
    return res;
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

fn getLabelIdx(self: *Parser, label: []const u8) ?u128 {
    for (self.label_addr.items) |label_addr|
        if (eql(u8, label_addr.label_str, label))
            return label_addr.label_idx;
    return null;
}

fn submitLabel(self: *Parser, label: []u8) !void {
    const label_len = label.len;
    var labels_buf_idx: usize = 0;
    var labels_buf: [0x1000]u8 = undefined;

    defer {
        labels_buf_idx += label_len;
        self.label_idx += 1;
    }

    const label_slice = labels_buf[labels_buf_idx .. labels_buf_idx + label_len];
    copyForwards(u8, label_slice, label);

    try self.label_addr.append(ImFineAssembler.Label2addr{
        .label_idx = self.label_idx,
        .label_str = label_slice,
        .addr_abs = undefined,
    });
}

fn processLineTokens(self: *Parser, str_BC_map: anytype, tokens: [3][]u8, tokens_sum: u32) !Code {
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
    curr_line_code.len = ImFineAssembler.getLen(curr_line_code.second_oprand);
    return curr_line_code;
}

pub fn parse(self: *Parser) !void {
    const str_BC_map = strBCMap().init();
    var curr_line_tokens: [3][]u8 = undefined;
    var idx: usize = 0;

    for (self.tokens.items) |token| {
        if (token == null) {
            defer idx = 0;
            const tokens_sum: u32 = @intCast(idx);
            const code: Code = try processLineTokens(
                self,
                str_BC_map,
                curr_line_tokens,
                tokens_sum,
            );
            try self.codes.append(code);
            continue;
        }
        curr_line_tokens[idx] = token.?;
        idx += 1;
    }
}
