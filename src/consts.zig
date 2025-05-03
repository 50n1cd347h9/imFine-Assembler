pub const EOF = ~@as(u8, @intCast(0));
pub const MAX_IDENT_LEN = 0x20;
pub const MAX_TOKEN_BUF = 0x1000;
pub const MAX_LABEL_BUF = 0x1000;
pub const MAX_TOKENS = 0x1000;
pub const instructions = [_][]const u8{
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
    "cmp",
    "jmp",
    "jg",
    "jz",
    "jl",
    "call",
    "ret",
    "nop",
};
pub const registers = [_][]const u8{
    "ip",
    "sp",
    "fp",
    "flag",
    "gr0",
    "gr1",
};

pub const keywds = instructions ++ registers;
