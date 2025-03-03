//! parser.zig is responsible for parsing assembly
//! and making identifier table
//!
//! Every function don't call nextToken() before read token first time except program()
//! Every function that read token call nextToken() at the end.

var token: Token = undefined;

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
};

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

//fn kindToError()

fn nextTokenVal(reader: anytype) ParseError!std.meta.Tuple(&[_]type{ Token, u32 }) {
    const actual = token.kind;
    const expected = .numberLiteral;
    if (actual == expected)
        return .{ nextToken(reader), token.val() };
    return ParseError.NumberExpected;
}

fn labelDef(reader: anytype) ParseError!void {
    token = nextToken(reader);
    token = nextTokenExpect(reader, .newline) catch |e| return e;
}

fn memoryReference(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {
            _ = 0; // do something
        },
        .numberLiteral => _ = token.val(),
        .sqbrac_r => return ParseError.UnexpectedCloseBracket,
        else => return ParseError.RegisterExpected,
    }

    token = nextToken(reader);
    token = nextTokenExpect(reader, .sqbrac_r) catch |e| return e;
}

fn insPush(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {
            _ = 0; // do something
        },
        .numberLiteral => {
            _ = token.val();
        },
        .sqbrac_l => {
            token = nextToken(reader);
            memoryReference(reader) catch |e| return e;
        },
        else => return ParseError.RegisterExpected,
    }
    token = nextToken(reader);
}

fn insPop(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {
            _ = 1; //do something
        },
        .sqbrac_l => {
            token = nextToken(reader);
            memoryReference(reader) catch |e| return e;
        },
        .numberLiteral => return ParseError.CannotPopIntoImmediate,
        else => return ParseError.RegisterExpected,
    }
    token = nextToken(reader);
}

fn insAdd(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {},
        else => return ParseError.RegisterExpected,
    }
    token = nextToken(reader);
    token = nextTokenExpect(reader, .comma) catch |e| return e;
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp, .flag, .ip => {},
        .numberLiteral => {
            _ = token.val();
        },
        else => return ParseError.UnexpectedToken,
    }
    token = nextToken(reader);
}

fn insAnd(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {},
        else => return error.RegisterExpected,
    }
    token = nextToken(reader);
    token = nextTokenExpect(reader, .comma) catch |e| return e;
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp, .flag, .ip => {},
        .numberLiteral => {
            _ = token.val();
        },
        else => return ParseError.UnexpectedToken,
    }
    token = nextToken(reader);
}

fn macroRet(reader: anytype) ParseError!void {
    _ = reader;
}

fn macroCall(reader: anytype) ParseError!void {
    _ = reader;
}

fn macroMov(reader: anytype) ParseError!void {
    _ = reader;
}

// TODO: handle macro e.g. call, ret, mov
fn instruction(reader: anytype) ParseError!void {
    switch (token.kind) {
        .push => {
            token = nextToken(reader);
            insPush(reader) catch |e| return e;
        },
        .pop => {
            token = nextToken(reader);
            insPop(reader) catch |e| return e;
        },
        .add => {
            token = nextToken(reader);
            insAdd(reader) catch |e| return e;
        },
        .sub => {},
        .mul => {},
        .div => {},
        .and_ => {
            token = nextToken(reader);
            insAnd(reader) catch |e| return e;
        },
        .or_ => {},
        .xor => {},
        .shl => {},
        .cmp => {},
        .jmp => {},
        .jg => {},
        .jz => {},
        .jl => {},
        .call => {
            token = nextToken(reader);
            macroCall(reader) catch |e| return e;
        },
        .ret => {},
        .nop => {},
        else => return error.InstructionExpected,
    }

    switch (token.kind) {
        .newline, .eof => token = nextToken(reader),
        else => return ParseError.UnexpectedToken,
    }
}

fn program(reader: anytype) ParseError!void {
    return while (true) {
        switch (token.kind) {
            .newline => token = nextToken(reader),
            .labelDef => labelDef(reader) catch |e| break e,
            .eof => break,
            else => instruction(reader) catch |e| break e,
        }
    };
}

fn parse(reader: anytype) ParseError!void {
    token = nextToken(reader);
    return program(reader);
}

test "and instruction" {
    runTest("-- program --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0, 1 
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try parse(reader);
}

test "newline expected" {
    runTest("-- newline expected --");

    defer testTokenizerInit();
    const program_str =
        \\hoge:ahi
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.NewlineExpected, parse(reader));
}

test "unexpected eof" {
    runTest("-- unexpected eof --");

    defer testTokenizerInit();
    const program_str =
        \\hoge:
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.NewlineExpected, parse(reader));
}

test "number expected" {
    runTest("-- number expected --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0, x
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.UnexpectedToken, parse(reader));
}

test "register expected" {
    runTest("-- register expected --");

    defer testTokenizerInit();
    const program_str =
        \\and XX, 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.RegisterExpected, parse(reader));
}

test "comma expected" {
    runTest("-- comma expected --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.CommaExpected, parse(reader));
}

test "instruction expected" {
    runTest("-- instruction expected --");

    defer testTokenizerInit();
    const program_str =
        \\gr0 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.InstructionExpected, parse(reader));
}

test "memory ref " {
    runTest("-- memory ref --");

    defer testTokenizerInit();
    const program_str =
        \\push [gr0]
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try parse(reader);
}

test "memory ref imm " {
    runTest("-- memory ref imm --");

    defer testTokenizerInit();
    const program_str =
        \\push [100]
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try parse(reader);
}

test "close expected" {
    runTest("-- close expected --");

    defer testTokenizerInit();
    const program_str =
        \\push [gr0
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.CloseBracketExpected, parse(reader));
}

test "unexpected close " {
    runTest("-- unexpected close --");

    defer testTokenizerInit();
    const program_str =
        \\push []
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.UnexpectedCloseBracket, parse(reader));
}
test "and instruction fail" {
    runTest("-- and instruction fail --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0, 1  ddd
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.UnexpectedToken, parse(reader));
}

const std = @import("std");
const tokenizer = @import("tokenizer.zig");
const property = @import("property.zig");
const Token = tokenizer.Token;
const TokenKind = tokenizer.TokenKind;
const testTokenizerInit = tokenizer.testTokenizerInit;
const runTest = property.runTest;
const nextToken = tokenizer.nextToken;
const fbs = std.io.fixedBufferStream;
const dbgprint = std.debug.print;
const panic = std.debug.panic;
const expect = std.testing.expect;
const expectError = std.testing.expectError;
