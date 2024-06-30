ld [gr0], 0x10
pop gr0
push gr1
ld gr0, [gr0]
ld gr1, 0x100
ld [gr1], [gr0]
;ld [gr1]  [gr0]
