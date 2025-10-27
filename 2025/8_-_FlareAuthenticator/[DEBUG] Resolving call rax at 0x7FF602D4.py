[DEBUG] Resolving call rax at 0x7FF602D48463
[DEBUG] Looking through 20 previous instructions
[DEBUG]   [0] 0x7FF602D48460: add rax, rdx
[DEBUG]     Found ADD from register (not supported yet)
[DEBUG]   [1] 0x7FF602D48456: movabs rdx, 0xd0f4fef88869b7a7
[DEBUG]   [2] 0x7FF602D4844F: mov rax, qword ptr [rip + 0x96902]
[DEBUG]     RIP-relative: 0x7FF602D4844F + 7 + 0x96902 = 0x7FF602DDED58
[DEBUG]     File offset: 0xAED58
[DEBUG]     Read base value: 0x6F8CEA1EDAC8C517
[DEBUG]   [3] 0x7FF602D4844C: mov rcx, qword ptr [rax]
[DEBUG]   [4] 0x7FF602D4844A: call rax
[DEBUG]   [5] 0x7FF602D48447: add rax, rdx
[DEBUG]     Found ADD from register (not supported yet)
[DEBUG]   [6] 0x7FF602D4843D: movabs rdx, 0x7bf32432283ec005
[DEBUG]   [7] 0x7FF602D48436: mov rax, qword ptr [rip + 0x9532b]
[DEBUG]     RIP-relative: 0x7FF602D48436 + 7 + 0x9532B = 0x7FF602DDD768
[DEBUG]     File offset: 0xAD768
[DEBUG]     Read base value: 0x18D8BB9779CF84D9
[DEBUG]   [8] 0x7FF602D48433: mov rcx, qword ptr [rax]
[DEBUG]   [9] 0x7FF602D48431: call rax
[DEBUG]   [10] 0x7FF602D4842E: add rax, rdx
[DEBUG]     Found ADD from register (not supported yet)
[DEBUG]   [11] 0x7FF602D48424: movabs rdx, 0xbd15572afe009b79
[DEBUG]   [12] 0x7FF602D4841D: mov rax, qword ptr [rip + 0xad4bc]
[DEBUG]     RIP-relative: 0x7FF602D4841D + 7 + 0xAD4BC = 0x7FF602DF58E0
[DEBUG]     File offset: 0xC58E0
[DEBUG]     Read base value: 0x9B54800089C15
[DEBUG]   [13] 0x7FF602D48416: mov rcx, qword ptr [rbp + 0xd0]
[DEBUG]   [14] 0x7FF602D48414: call rax
[DEBUG]   [15] 0x7FF602D48411: add rax, r8
[DEBUG]     Found ADD from register (not supported yet)
[DEBUG]   [16] 0x7FF602D48407: movabs r8, 0x23ef68757313f713
[DEBUG]   [17] 0x7FF602D48400: mov rax, qword ptr [rip + 0x90709]
[DEBUG]     RIP-relative: 0x7FF602D48400 + 7 + 0x90709 = 0x7FF602DD8B10
[DEBUG]     File offset: 0xA8B10
[DEBUG]     Read base value: 0x63A964F415AC4547
[DEBUG]   [18] 0x7FF602D483FC: add rdx, 0x10
[DEBUG]   [19] 0x7FF602D483F9: mov rdx, qword ptr [rax]
[DEBUG] Failed to resolve (base=7181382080317375815, add=None)

00007FF602D48463  call     rax                               ; indirect call (unresolved)