//! parser.zig is responsible for parsing assembly
//! and making identifier table
//!
//! Every function don't call nextToken() before read token first time except program()
//! Every function that read token call nextToken() at the end.
//!

var labels = Labels{};
var buffer = [_]u8{0} ** 0x1000;
var fba = std.heap.FixedBufferAllocator.init(&buffer);
const a = fba.allocator();

var token: Token = undefined;
var code: Code = Code.init();
var encoder: Encoder = undefined;

const ParseError = error{
    CommaExpected,
    InstructionExpected,
    TokenAfterInstruction,
    NumberExpected,
    RegisterExpected,
    NewlineExpected,
    UnexpectedEof,
    CloseBracketExpected,
    UnexpectedCloseBracket,
    CannotPopIntoImmediate,
    UnexpectedToken,
    LabelDefExpected,
    LabelDefinedAlready,
};

pub const Label = struct {
    token: Token,
    idx: usize,
};
const Labels: type = std.MultiArrayList(Label);

// emit parsed instruction
fn emit() void {
    // do nothing
    //if (!encoder.isInitialized())
    //    return;

    encoder.emitCode(&code);
}

fn regstr2Num(comptime reg: []const u8) u3 {
    for (consts.registers, 0..) |_reg, i| {
        if (std.mem.eql(u8, reg, _reg))
            return @as(u3, @intCast(i));
    } else @panic("aajfdkas;");
}

fn getRegNum(reg: TokenKind) ParseError!u3 {
    return switch (reg) {
        .ip => regstr2Num("ip"),
        .sp => regstr2Num("sp"),
        .fp => regstr2Num("fp"),
        .flag => regstr2Num("flag"),
        .gr0 => regstr2Num("gr0"),
        .gr1 => regstr2Num("gr1"),
        else => ParseError.RegisterExpected,
    };
}

fn getOpcode(comptime inst: []const u8) u6 {
    for (consts.instructions, 0..) |_inst, i| {
        if (std.mem.eql(u8, inst, _inst))
            return @as(u6, @intCast(i));
    } else @panic("ghoe");
}

/// return nextToken() if token kind actual == expected
fn nextTokenExpect(reader: anytype, expected: TokenKind) ParseError!Token {
    const actual = token.kind;
    if (actual == expected)
        return nextToken(reader);

    return switch (expected) {
        .comma => ParseError.CommaExpected,
        .numberLiteral => ParseError.NumberExpected,
        .newline => ParseError.NewlineExpected,
        .sqbrac_r => ParseError.CloseBracketExpected,
        else => ParseError.UnexpectedToken,
    };
}

//fn loolupLabels(_token: Token) ?Token {
//    _ = _token;
//}

fn labelDefExists() ParseError!bool {
    const current = token;

    if (current.kind != .labelDef)
        return ParseError.LabelDefExpected;

    for (labels.items(.token)) |label_token| {
        if (label_token.kind == .labelDef and label_token.id == current.id)
            return true;
    }
    return false;
}

fn submitLabel() ParseError!void {
    switch (token.kind) {
        .labelDef => {
            if (try labelDefExists())
                return ParseError.LabelDefinedAlready;
        },
        .label => {},
        else => return ParseError.UnexpectedToken,
    }

    labels.append(a, .{
        .token = token,
        .idx = tokenizer.tokens.len - 1,
    }) catch @panic("hogehgoe");
}

fn labelDef(reader: anytype) ParseError!void {
    try submitLabel();
    token = nextToken(reader);
    token = try nextTokenExpect(reader, .newline);
}

// Memory reference is always second operand.
fn memoryReference(reader: anytype) ParseError!void {
    std.debug.print("@memoryReference: {}\n", .{token.kind});

    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {
            code.len = Code.Len.bit8;
            code.ext = Code.Ext.ref_reg;
            code.imm_reg = try getRegNum(token.kind);
        },
        .numberLiteral => {
            code.len = Code.Len.bit32;
            code.ext = Code.Ext.ref_imm;
            code.imm_reg = token.id;
        },
        .sqbrac_r => return ParseError.UnexpectedCloseBracket,
        else => return ParseError.RegisterExpected,
    }

    token = nextToken(reader); // read sqbrac_r
    token = try nextTokenExpect(reader, .sqbrac_r);
}

fn insPush(reader: anytype) ParseError!void {
    code.opcode = getOpcode("push");

    switch (token.kind) {
        .ip, .sp, .fp, .gr0, .gr1 => {
            code.len = Code.Len.bit8;
            code.ext = Code.Ext.reg;
            code.imm_reg = try getRegNum(token.kind);
        },
        .numberLiteral => {
            code.len = Code.Len.bit32; // TODO: select len
            code.ext = Code.Ext.imm;
            code.imm_reg = token.id;
        },
        .sqbrac_l => {
            token = nextToken(reader);
            try memoryReference(reader);
        },
        else => return ParseError.RegisterExpected,
    }
    token = nextToken(reader);
    std.debug.print("@insPush: {}\n", .{token.kind});
}

fn insPop(reader: anytype) ParseError!void {
    code.opcode = getOpcode("pop");

    switch (token.kind) {
        // ip and flag is read-only.
        // fp, sp cannot be popped into.
        .gr0, .gr1 => {
            code.len = Code.Len.bit8;
            code.ext = Code.Ext.reg;
            code.imm_reg = try getRegNum(token.kind);
        },
        .sqbrac_l => {
            token = nextToken(reader);
            try memoryReference(reader);
        },
        .numberLiteral => return ParseError.CannotPopIntoImmediate,
        else => return ParseError.RegisterExpected,
    }
}

fn insAdd(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {},
        else => return ParseError.RegisterExpected,
    }
    token = nextToken(reader);
    token = try nextTokenExpect(reader, .comma);
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp, .flag, .ip => {},
        .numberLiteral => {
            _ = token.id;
        },
        else => return ParseError.UnexpectedToken,
    }
}

fn insDiv(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {},
        else => return ParseError.RegisterExpected,
    }
    token = nextToken(reader);
    token = try nextTokenExpect(reader, .comma);
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp, .flag, .ip => {},
        .numberLiteral => {
            _ = token.id;
        },
        else => return ParseError.UnexpectedToken,
    }
}

fn insCmp(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp, .flag, .ip => {},
        .numberLiteral => {
            _ = token.id;
        },
        else => return ParseError.UnexpectedToken,
    }
    token = nextToken(reader);
    token = try nextTokenExpect(reader, .comma);
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp, .flag, .ip => {},
        .numberLiteral => {
            _ = token.id;
        },
        else => return ParseError.UnexpectedToken,
    }
}

// TODO: jg, jl, jz etc.
fn insJmp(reader: anytype) ParseError!void {
    _ = reader;
    switch (token.kind) {
        .gr0, .gr1 => {}, // TODO: implement
        else => return error.RegisterExpected,
    }
}

fn macroRet(reader: anytype) ParseError!void {
    token = nextToken(reader);
}

fn macroCall(reader: anytype) ParseError!void {
    _ = reader;
    switch (token.kind) {
        .gr0, .gr1 => {},
        .label => {
            _ = 0;
        },
        else => return ParseError.UnexpectedToken,
    }
}

// 1st operand: dst
// 2nd operand: src
fn macroMov(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1 => {}, // TODO
        .sqbrac_l => {
            token = nextToken(reader);
            try memoryReference(reader);
        },
        else => return ParseError.UnexpectedToken,
    }
    token = nextToken(reader);
    token = try nextTokenExpect(reader, .comma);
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp, .flag, .ip => {},
        .numberLiteral => {
            _ = token.id;
        },
        .sqbrac_l => {
            token = nextToken(reader);
            try memoryReference(reader);
        },
        else => return ParseError.UnexpectedToken,
    }
}

// TODO: handle macro e.g. call, ret, mov
// TODO: backpatch
fn instruction(reader: anytype) ParseError!void {
    switch (token.kind) {
        .push => {
            token = nextToken(reader);
            try insPush(reader);
        },
        .pop => {
            token = nextToken(reader);
            try insPop(reader);
        },
        .add, .sub, .mul, .and_, .or_, .xor, .shl => {
            token = nextToken(reader);
            try insAdd(reader);
        },
        .div => {
            token = nextToken(reader);
            try insDiv(reader);
        },
        .cmp => {
            token = nextToken(reader);
            try insCmp(reader);
        },
        .jmp, .jg, .jz, .jl => {
            token = nextToken(reader);
            try insJmp(reader);
        },
        .call => {
            token = nextToken(reader);
            try macroCall(reader);
        },
        .ret => {
            token = nextToken(reader);
            try macroRet(reader);
        },
        .mov => {
            token = nextToken(reader);
            try macroMov(reader);
        },
        //.nop => {},
        else => return ParseError.InstructionExpected,
    }

    token = nextToken(reader); // Read newline or eof.

    switch (token.kind) {
        .newline, .eof => token = nextToken(reader),
        else => {
            std.debug.print("@instruction: {}\n", .{token.kind});
            return ParseError.UnexpectedToken;
        },
    }
}

fn program(reader: anytype) ParseError!void {
    return while (true) {
        switch (token.kind) {
            .newline => token = nextToken(reader),
            .labelDef => try labelDef(reader),
            .eof => break,
            else => {
                code = Code.init();
                try instruction(reader);
                emit();
            },
        }
    };
}

fn init() void {
    labels.clearAndFree(a);
    tokenizer.init();
    encoder = Encoder.init();
}

fn parse(reader: anytype) ParseError!void {
    init();
    token = nextToken(reader);
    try program(reader);
    //std.debug.print("len: {d}\n", .{tokenizer.tokens.len});
    //std.debug.print("len: {any}\n", .{tokenizer.tokens.get(1)});
}

test "and instruction" {
    const program_str =
        \\and gr0, 1 
        \\and gr0, 1
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try parse(reader);
}

test "newline expected" {
    const program_str =
        \\hoge:ahi
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.NewlineExpected, parse(reader));
}

test "unexpected eof" {
    const program_str =
        \\hoge:
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.NewlineExpected, parse(reader));
}

test "number expected" {
    const program_str =
        \\and gr0, x
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.UnexpectedToken, parse(reader));
}

test "register expected" {
    const program_str =
        \\and XX, 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.RegisterExpected, parse(reader));
}

test "comma expected" {
    const program_str =
        \\and gr0 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.CommaExpected, parse(reader));
}

test "instruction expected" {
    const program_str =
        \\gr0 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.InstructionExpected, parse(reader));
}

test "memory ref " {
    const program_str =
        \\push [gr0]
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try parse(reader);
}

test "memory ref imm " {
    const program_str =
        \\push [100]
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try parse(reader);
}

test "close expected" {
    const program_str =
        \\push [gr0
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.CloseBracketExpected, parse(reader));
}

test "unexpected close " {
    const program_str =
        \\push []
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.UnexpectedCloseBracket, parse(reader));
}

test "and instruction fail" {
    const program_str =
        \\and gr0, 1  ddd
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.UnexpectedToken, parse(reader));
}

test "call" {
    const program_str =
        \\call ddd
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try parse(reader);
    //try expectError(ParseError.UnexpectedToken, parse(reader));
}

fn testParse(prog_str: []const u8) !void {
    var stream = fbs(prog_str);
    const reader = stream.reader();
    try parse(reader);
}

test "push" {
    std.debug.print("!push!\n", .{});
    const test_str =
        \\push [0x1]
        \\push [gr1]
        //\\push gr0
        //\\push 100
    ;
    try testParse(test_str);

    //try expectEqual(encoder.codes.slice().len, 4);
    //var elem = encoder.codes.pop();
    //try expectEqual(
    //    elem,
    //    Code{
    //        .opcode = getOpcode("push"),
    //        .ext = Code.Ext.imm,
    //        .len = Code.Len.bit32,
    //        .reg = 0,
    //        .padding = 0,
    //        .imm_reg = 100,
    //    },
    //);
    //elem = encoder.codes.pop();
    //try expectEqual(
    //    elem,
    //    Code{
    //        .opcode = getOpcode("push"),
    //        .ext = Code.Ext.reg,
    //        .len = Code.Len.bit8,
    //        .reg = 0,
    //        .padding = 0,
    //        .imm_reg = @intCast(try getRegNum(.gr0)),
    //    },
    //);
    //elem = encoder.codes.pop();
    //try expectEqual(
    //    elem,
    //    Code{
    //        .opcode = getOpcode("push"),
    //        .ext = Code.Ext.ref_reg,
    //        .len = Code.Len.bit8,
    //        .reg = 0,
    //        .padding = 0,
    //        .imm_reg = @intCast(try getRegNum(.gr1)),
    //    },
    //);
    //elem = encoder.codes.pop();
    //try expectEqual(
    //    elem,
    //    Code{
    //        .opcode = getOpcode("push"),
    //        .ext = Code.Ext.ref_imm,
    //        .len = Code.Len.bit8,
    //        .reg = 0,
    //        .padding = 0,
    //        .imm_reg = 0x1,
    //    },
    //);
}

const std = @import("std");
const consts = @import("consts.zig");

const tokenizer = @import("tokenizer.zig");
const Token = tokenizer.Token;
const TokenKind = tokenizer.TokenKind;
const nextToken = tokenizer.nextToken;

const Encoder = @import("encoder.zig");
const Code = Encoder.Code;

const property = @import("property.zig");

const fbs = std.io.fixedBufferStream;
const dbgprint = std.debug.print;
const panic = std.debug.panic;
const expect = std.testing.expect;
const expectError = std.testing.expectError;
const expectEqual = std.testing.expectEqual;
