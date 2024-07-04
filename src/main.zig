const std = @import("std");
const io = std.io;
const fs = std.fs;
const stdin = io.getStdIn().reader();
const stdout = io.getStdOut().writer();
const process = std.process;
const print = std.debug.print;
const eql = std.mem.eql;
const pow = std.math.pow;
const shr = std.math.shr;
const ArrayList = std.ArrayList;
const mem = std.mem;
const copyForwards = mem.copyForwards;
const builtin = std.builtin;

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

fn toInt(buf: []const u8) !u128 {
    var res: u128 = 0;
    if (buf.len > 2 and buf[0] == '0' and buf[1] == 'x') {
        res = try std.fmt.parseInt(u128, buf[2..buf.len], 16);
    } else {
        res = try std.fmt.parseInt(u128, buf, 10);
    }
    return res;
}

fn nextChar(buf: []u8) ?u8 {
    const char = if (buf.len > 2) buf[1] else null;
    return char;
}

const ImFineAssembly = struct {
    src_name: []u8,
    dst_name: []u8,
    src_file: std.fs.File,
    dst_file: std.fs.File,
    input_reader: std.fs.File.Reader,
    output_writer: std.fs.File.Writer,
    line_buffer: [0x100]u8,
    tokens: ArrayList([]u8),
    curr_line_code: Code,
    codes: ArrayList(Code),
    label_addr: ArrayList(Label2addr),
    label_slots: ArrayList(LabelSlot),
    out_buf: ArrayList(u8),
    label_idx: ByteWidth,

    const ByteWidth: type = u32;
    const COMMA: u8 = ',';
    const SEMICOLON: u8 = ';';
    const SPACE: u8 = ' ';
    const SQUARE_BRACKET_OPEN = '[';
    const SQUARE_BRACKET_CLOSE = ']';
    const INDENT = '\t';
    const COLON: u8 = ':';
    const EOL = '\x00';
    const BC_imm: u2 = 0b00;
    const BC_reg: u2 = 0b01;
    const BC_imm_ref: u2 = 0b10;
    const BC_reg_ref: u2 = 0b11;
    const LABEL: u8 = 0b11000000;

    var str_BC_map: [instructions.len + registers.len]StrBc = undefined;
    var labels_buf: [0x1000]u8 = undefined;
    var labels_buf_idx: usize = 0;
    var begin_idx: u32 = 0;
    var curr_idx: u32 = 0;
    var allocator: std.mem.Allocator = undefined;
    const filename_len = 0x50;
    var file_name_buf: [filename_len * 2]u8 = undefined;

    // the order is matter
    // ldr, ldm
    const instructions = [_][]const u8{ "push", "pop", "add", "sub", "mul", "div", "and", "or", "xor", "shl", "ld", "ld", "cmp", "jmp", "jg", "jz", "jl", "call", "ret", "nop" };
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
        label: []u8,
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

    fn init(self: *ImFineAssembly, _allocator: std.mem.Allocator) !void {
        allocator = _allocator;
        self.label_idx = 0;
        for (instructions, 0..) |instruction, i| {
            str_BC_map[i].name = instruction;
            str_BC_map[i].bc = @as(u8, @intCast(i));
        }
        for (registers, 0..) |register, i| {
            str_BC_map[instructions.len + i].name = register;
            str_BC_map[instructions.len + i].bc = @as(u8, @intCast(i));
        }

        @memset(&file_name_buf, 0);
    }

    // *const [][:0]u8 = pointer to an array of zero terminated const u8 values
    fn parseArgs(self: *ImFineAssembly, args_p: *const [][:0]u8) !void {
        if (args_p.len < 2) {
            return ArgError.TooFewArgs;
        }

        // for (args_p.*, 0..) |arg, i| {
        //     _ = i;
        // }
        copyForwards(u8, &file_name_buf, args_p.*[1]);
        self.asignOutputName();
    }

    fn asignOutputName(self: *ImFineAssembly) void {
        const extension = [4:0]u8{ '.', 'b', 'i', 'n' };

        const src_len = for (0..file_name_buf.len) |i| {
            if (file_name_buf[i] == EOL) {
                break @as(u8, @intCast(i));
            }
        } else blk: {
            break :blk @as(u8, @intCast(file_name_buf.len));
        };

        self.src_name = file_name_buf[0..src_len];

        const dst_len = for (0..src_len) |i| {
            if (file_name_buf[i] == '.') {
                break @as(u8, @intCast(i + extension.len));
            }
            file_name_buf[src_len + i] = self.src_name[i];
        } else blk: {
            break :blk @as(u8, @intCast(src_len + extension.len));
        };

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

    fn getBc(bcmap: [*]StrBc, name: []const u8) u8 {
        for (0..str_BC_map.len) |i| {
            if (std.mem.eql(u8, bcmap[i].name, name))
                return bcmap[i].bc;
        }
        return 0;
    }

    fn getLabelIdx(self: *ImFineAssembly, label: []const u8) ?u128 {
        for (self.label_addr.items) |label_addr|
            if (std.mem.eql(u8, label_addr.label, label))
                return label_addr.label_idx;
        return null;
    }

    fn isRegister(buf: []const u8) bool {
        for (registers) |register|
            if (std.mem.eql(u8, buf, register))
                return true;
        return false;
    }

    fn isOpcode(buf: []const u8) bool {
        for (instructions) |instruction|
            if (std.mem.eql(u8, buf, instruction))
                return true;
        return false;
    }

    fn isImm(buf: []const u8) bool {
        var res: ?u128 = 0;
        for ([2]u8{ 10, 16 }) |base| {
            if (buf.len > 2 and buf[0] == '0' and buf[1] == 'x') {
                res = std.fmt.parseInt(u128, buf[2..buf.len], base) catch null;
            } else {
                res = std.fmt.parseInt(u128, buf, base) catch null;
            }
            if (base == 16) {
                if (res == null) {
                    return false;
                } else {
                    return true;
                }
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

    fn submitLabel(self: *ImFineAssembly, label: []u8) !void {
        const label_len = label.len;
        defer {
            labels_buf_idx += label_len;
            self.label_idx += 1;
        }

        const label_slice = labels_buf[labels_buf_idx .. labels_buf_idx + label_len];
        copyForwards(u8, label_slice, label);

        try self.label_addr.append(Label2addr{
            .label_idx = self.label_idx,
            .label = label_slice,
            .addr_abs = 0,
        });
    }

    fn parse(self: *ImFineAssembly) !void {
        var curr_token_type: Token = undefined;
        var prev_token_type: Token = undefined;
        const tokens_sum = self.tokens.items.len;
        defer {
            self.curr_line_code.len = getLen(self.curr_line_code.second_oprand);
        }

        for (self.tokens.items) |token| {
            curr_token_type = getTokenType(token);
            defer {
                prev_token_type = curr_token_type;
            }
            switch (curr_token_type) {
                Token.Opcode => self.curr_line_code.opcode = getBc(&str_BC_map, token),
                Token.Register => {
                    if (tokens_sum == 3) {
                        self.curr_line_code.first_oprand = getBc(&str_BC_map, token);
                    } else {
                        self.curr_line_code.second_oprand = getBc(&str_BC_map, token);
                        self.curr_line_code.ext = BC_reg;
                    }
                },
                Token.Imm => {
                    const int_num = try toInt(token);
                    self.curr_line_code.second_oprand = int_num;
                    self.curr_line_code.ext = BC_imm;
                },
                // [], ref
                Token.Ref => {
                    const inner = token[1 .. token.len - 1];
                    curr_token_type = getTokenType(inner);
                    if (curr_token_type == Token.Register) {
                        // ld
                        if (prev_token_type == Token.Opcode) {
                            self.curr_line_code.opcode += 1;
                            self.curr_line_code.first_oprand = getBc(&str_BC_map, inner);
                        } else {
                            self.curr_line_code.second_oprand = getBc(&str_BC_map, inner);
                            self.curr_line_code.ext = BC_reg_ref;
                        }
                    } else
                    //imm
                    {
                        const int_num = try toInt(inner);
                        self.curr_line_code.second_oprand = int_num;
                        self.curr_line_code.ext = BC_imm_ref;
                    }
                },
                Token.Label => {
                    const label = token[0 .. token.len - 1];
                    self.curr_line_code.opcode = LABEL;
                    // if already submitted
                    if (self.getLabelIdx(label)) |idx| {
                        self.curr_line_code.second_oprand = idx;
                        continue;
                    }
                    self.curr_line_code.second_oprand = self.label_idx;
                    try self.submitLabel(label);
                },
                Token.InvalidToken => {
                    if (prev_token_type == Token.Opcode) {
                        if (self.getLabelIdx(token)) |idx| {
                            self.curr_line_code.second_oprand = idx;
                        } else {
                            self.curr_line_code.opcode |= LABEL;
                            self.curr_line_code.second_oprand = self.label_idx;
                            try self.submitLabel(token);
                        }
                    } else {
                        return SyntaxError.UnknownToken;
                    }
                },
            }
        }
    }

    fn nextToken(line: []u8) !?[]u8 {
        const buf_end = line.len;
        var token_str: ?[]u8 = null;

        while (begin_idx < buf_end) : (curr_idx += 1) {
            defer {
                begin_idx = curr_idx;
            }
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
                    } else {
                        return SyntaxError.CloseSquareBracketNeeded;
                    }
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
                    } else {
                        curr_idx = @intCast(buf_end);
                    }
                    token_str = line[begin_idx..curr_idx];
                    break;
                },
            }
        }

        return token_str;
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

    fn resoluteLabelAddr(self: *ImFineAssembly, idx: u128, addr: usize) void {
        self.label_addr.items[@intCast(idx)].addr_abs = @intCast(addr);
    }

    fn getLabelAddr(self: *ImFineAssembly, idx: u128) ByteWidth {
        return self.label_addr.items[@intCast(idx)].addr_abs;
    }

    fn getRelative(origin: ByteWidth, dst: ByteWidth) ByteWidth {
        const abs = if (origin > dst) (origin - dst) else (dst - origin);
        const minus = if (origin > dst) true else false;

        if (minus)
            return abs & (0b1 << (@sizeOf(ByteWidth) * 8 - 1));
        return abs;
    }

    fn writeAddr(self: *ImFineAssembly, slot_place: ByteWidth, value: ByteWidth) void {
        const mask: ByteWidth = 0xff;
        const src_bytes = @sizeOf(ByteWidth);

        for (0..src_bytes) |i| {
            const ref = i + @as(ByteWidth, @intCast(slot_place));
            const ofs: u5 = @intCast(i);
            const byte = shr(ByteWidth, value, ofs * 8) & mask;
            self.out_buf.items[ref] = @as(u8, @intCast(byte));
        }
    }

    fn resoluteLabelSlots(self: *ImFineAssembly) !void {
        for (self.label_slots.items) |slot| {
            const idx = slot.label_idx;

            search_label: for (self.label_addr.items) |label| {
                if (label.label_idx == idx) {
                    const addr_abs = label.addr_abs;
                    const slot_place = slot.place;
                    const next_ins_addr = slot_place + @sizeOf(ByteWidth);
                    const rel_addr = getRelative(next_ins_addr, addr_abs);
                    self.writeAddr(slot_place, rel_addr);
                    break :search_label;
                }
            } else {
                return SyntaxError.LabelNotFound;
            }
        }
    }

    fn getSecondOprandBytes(len: u3) u8 {
        return if (len == 0) 1 else @divExact(pow(u8, 2, len + 2), 8);
    }

    fn toBinary(self: *ImFineAssembly) !void {
        var buf: [0x50]u8 = undefined;
        var binary_idx: usize = 0;
        self.label_slots = ArrayList(LabelSlot).init(allocator);
        defer self.label_slots.deinit();

        for (self.codes.items) |*code| {
            var index: u8 = 0;
            defer binary_idx += index;

            if (code.opcode == LABEL) {
                self.resoluteLabelAddr(code.second_oprand, binary_idx);
                continue;
            }

            if (code.opcode & LABEL == LABEL) {
                try self.label_slots.append(LabelSlot{
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

        try self.resoluteLabelSlots();
    }

    fn nextLine(self: *ImFineAssembly) !?[]u8 {
        @memset(&self.line_buffer, 0);
        const line = try self.input_reader.readUntilDelimiterOrEof(
            &self.line_buffer,
            '\n',
        );
        if (line == null)
            return line;
        if (@import("builtin").os.tag == .windows)
            std.mem.trimRight(u8, self.line_buffer, "\r");
        return if (line.?.len == 0) self.nextLine() else line;
    }

    fn errorHandler(self: *ImFineAssembly) void {
        print("line: {s}", .{self.line_buffer});
        fs.cwd().deleteFile(
            self.dst_name,
        ) catch unreachable;
    }

    fn assemble(self: *ImFineAssembly) !void {
        errdefer {
            self.errorHandler();
        }

        self.src_file = try fs.cwd().openFile(
            self.src_name,
            .{ .mode = .read_only },
        );
        self.dst_file = try fs.cwd().createFile(
            self.dst_name,
            .{},
        );
        self.input_reader = self.src_file.reader();
        self.codes = ArrayList(Code).init(allocator);
        self.label_addr = ArrayList(Label2addr).init(allocator);
        self.out_buf = ArrayList(u8).init(allocator);
        self.output_writer = self.dst_file.writer();
        defer {
            self.label_addr.deinit();
            self.src_file.close();
            self.codes.deinit();
            self.out_buf.deinit();
            self.dst_file.close();
        }

        while (try self.nextLine()) |line| {
            self.curr_line_code = emptyCode();
            self.tokens = ArrayList([]u8).init(allocator);
            defer {
                curr_idx = 0;
                begin_idx = 0;
                self.tokens.deinit();
            }
            while (try nextToken(line)) |token|
                try self.tokens.append(token);
            if (self.tokens.items.len == 0)
                continue;
            try self.parse();
            try self.codes.append(self.curr_line_code);
        }

        try self.toBinary();
        try self.output_writer.writeAll(self.out_buf.items);
    }
};

pub fn main() !void {
    const args = try process.argsAlloc(std.heap.page_allocator);
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        process.argsFree(std.heap.page_allocator, args);
        const deinit_status = gpa.deinit();
        _ = deinit_status;
    }

    var hoge: ImFineAssembly = undefined;
    try hoge.init(allocator);
    try hoge.parseArgs(&args);
    hoge.assemble() catch |err| {
        print("{!}\n", .{err});
    };
}
