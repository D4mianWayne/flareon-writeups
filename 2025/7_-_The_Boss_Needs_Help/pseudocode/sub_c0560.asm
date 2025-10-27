t:00007FF7875C0560                 mov     [rsp+arg_8], rbx
.text:00007FF7875C0565                 mov     [rsp+arg_10], rbp
.text:00007FF7875C056A                 mov     [rsp+arg_18], rsi
.text:00007FF7875C056F                 push    rdi
.text:00007FF7875C0570                 push    r12
.text:00007FF7875C0572                 push    r13
.text:00007FF7875C0574                 push    r14
.text:00007FF7875C0576                 push    r15
.text:00007FF7875C0578                 mov     r12, rdx
.text:00007FF7875C057B                 mov     rsi, rcx
.text:00007FF7875C057E                 sub     r12, rcx
.text:00007FF7875C0581                 mov     r9d, 4
.text:00007FF7875C0587                 nop     word ptr [rax+rax+00000000h]
.text:00007FF7875C0590
.text:00007FF7875C0590 loc_7FF7875C0590:                       ; CODE XREF: sub_7FF7875C0560+54↓j
.text:00007FF7875C0590                 mov     r8d, 4
.text:00007FF7875C0596                 db      66h, 66h
.text:00007FF7875C0596                 nop     word ptr [rax+rax+00000000h]
.text:00007FF7875C05A0
.text:00007FF7875C05A0 loc_7FF7875C05A0:                       ; CODE XREF: sub_7FF7875C0560+4E↓j
.text:00007FF7875C05A0                 movzx   eax, byte ptr [r12+rcx]
.text:00007FF7875C05A5                 xor     [rcx], al
.text:00007FF7875C05A7                 inc     rcx
.text:00007FF7875C05AA                 sub     r8, 1
.text:00007FF7875C05AE                 jnz     short loc_7FF7875C05A0
.text:00007FF7875C05B0                 sub     r9, 1
.text:00007FF7875C05B4                 jnz     short loc_7FF7875C0590
.text:00007FF7875C05B6                 lea     rbp, [r12+10h]
.text:00007FF7875C05BB                 mov     [rsp+28h+arg_0], 0Dh
.text:00007FF7875C05C4                 lea     r10, byte_7FF7879DB8A0
.text:00007FF7875C05CB                 nop     dword ptr [rax+rax+00h]
.text:00007FF7875C05D0
.text:00007FF7875C05D0 loc_7FF7875C05D0:                       ; CODE XREF: sub_7FF7875C0560+206↓j
.text:00007FF7875C05D0                 mov     r8, rsi
.text:00007FF7875C05D3                 mov     r9d, 4
.text:00007FF7875C05D9                 nop     dword ptr [rax+00000000h]
.text:00007FF7875C05E0
.text:00007FF7875C05E0 loc_7FF7875C05E0:                       ; CODE XREF: sub_7FF7875C0560+AC↓j
.text:00007FF7875C05E0                 mov     rcx, r8
.text:00007FF7875C05E3                 mov     edx, 4
.text:00007FF7875C05E8                 nop     dword ptr [rax+rax+00000000h]
.text:00007FF7875C05F0
.text:00007FF7875C05F0 loc_7FF7875C05F0:                       ; CODE XREF: sub_7FF7875C0560+A3↓j
.text:00007FF7875C05F0                 movzx   eax, byte ptr [rcx]
.text:00007FF7875C05F3                 lea     rcx, [rcx+4]
.text:00007FF7875C05F7                 movzx   eax, byte ptr [rax+r10]
.text:00007FF7875C05FC                 mov     [rcx-4], al
.text:00007FF7875C05FF                 sub     rdx, 1
.text:00007FF7875C0603                 jnz     short loc_7FF7875C05F0
.text:00007FF7875C0605                 inc     r8
.text:00007FF7875C0608                 sub     r9, 1
.text:00007FF7875C060C                 jnz     short loc_7FF7875C05E0
.text:00007FF7875C060E                 movzx   eax, byte ptr [rsi+5]
.text:00007FF7875C0612                 lea     r14, [rsi+2]
.text:00007FF7875C0616                 movzx   ecx, byte ptr [rsi+1]
.text:00007FF7875C061A                 mov     r15d, 4
.text:00007FF7875C0620                 mov     [rsi+1], al
.text:00007FF7875C0623                 movzx   eax, byte ptr [rsi+9]
.text:00007FF7875C0627                 mov     [rsi+5], al
.text:00007FF7875C062A                 movzx   eax, byte ptr [rsi+0Dh]
.text:00007FF7875C062E                 mov     [rsi+9], al
.text:00007FF7875C0631                 movzx   eax, byte ptr [rsi+0Ah]
.text:00007FF7875C0635                 mov     [rsi+0Dh], cl
.text:00007FF7875C0638                 movzx   ecx, byte ptr [rsi+2]
.text:00007FF7875C063C                 mov     [rsi+2], al
.text:00007FF7875C063F                 movzx   eax, byte ptr [rsi+0Eh]
.text:00007FF7875C0643                 mov     [rsi+0Ah], cl
.text:00007FF7875C0646                 movzx   ecx, byte ptr [rsi+6]
.text:00007FF7875C064A                 mov     [rsi+6], al
.text:00007FF7875C064D                 movzx   eax, byte ptr [rsi+0Fh]
.text:00007FF7875C0651                 mov     [rsi+0Eh], cl
.text:00007FF7875C0654                 movzx   ecx, byte ptr [rsi+3]
.text:00007FF7875C0658                 mov     [rsi+3], al
.text:00007FF7875C065B                 movzx   eax, byte ptr [rsi+0Bh]
.text:00007FF7875C065F                 mov     [rsi+0Fh], al
.text:00007FF7875C0662                 movzx   eax, byte ptr [rsi+7]
.text:00007FF7875C0666                 mov     [rsi+0Bh], al
.text:00007FF7875C0669                 mov     [rsi+7], cl
.text:00007FF7875C066C                 nop     dword ptr [rax+00h]
.text:00007FF7875C0670
.text:00007FF7875C0670 loc_7FF7875C0670:                       ; CODE XREF: sub_7FF7875C0560+1BA↓j
.text:00007FF7875C0670                 movzx   edi, byte ptr [r14-2]
.text:00007FF7875C0675                 movzx   r8d, byte ptr [r14-1]
.text:00007FF7875C067A                 movzx   edx, dil
.text:00007FF7875C067E                 movzx   ebx, byte ptr [r14+1]
.text:00007FF7875C0683                 xor     dl, r8b
.text:00007FF7875C0686                 movzx   r10d, byte ptr [r14]
.text:00007FF7875C068A                 lea     r14, [r14+4]
.text:00007FF7875C068E                 movzx   eax, dl
.text:00007FF7875C0691                 movzx   r9d, bl
.text:00007FF7875C0695                 shr     al, 7
.text:00007FF7875C0698                 add     dl, dl
.text:00007FF7875C069A                 movzx   eax, al
.text:00007FF7875C069D                 xor     r9b, r10b
.text:00007FF7875C06A0                 imul    ecx, eax, 1Bh
.text:00007FF7875C06A3                 movzx   r11d, r9b
.text:00007FF7875C06A7                 xor     r11b, dil
.text:00007FF7875C06AA                 xor     r11b, r8b
.text:00007FF7875C06AD                 xor     cl, dl
.text:00007FF7875C06AF                 movzx   edx, r8b
.text:00007FF7875C06B3                 xor     cl, dil
.text:00007FF7875C06B6                 xor     dl, r10b
.text:00007FF7875C06B9                 xor     cl, r11b
.text:00007FF7875C06BC                 movzx   eax, dl
.text:00007FF7875C06BF                 mov     [r14-6], cl
.text:00007FF7875C06C3                 xor     dil, bl
.text:00007FF7875C06C6                 shr     al, 7
.text:00007FF7875C06C9                 add     dl, dl
.text:00007FF7875C06CB                 movzx   eax, al
.text:00007FF7875C06CE                 imul    ecx, eax, 1Bh
.text:00007FF7875C06D1                 movzx   eax, r9b
.text:00007FF7875C06D5                 shr     al, 7
.text:00007FF7875C06D8                 add     r9b, r9b
.text:00007FF7875C06DB                 movzx   eax, al
.text:00007FF7875C06DE                 xor     cl, dl
.text:00007FF7875C06E0                 xor     cl, r8b
.text:00007FF7875C06E3                 xor     cl, r11b
.text:00007FF7875C06E6                 mov     [r14-5], cl
.text:00007FF7875C06EA                 imul    ecx, eax, 1Bh
.text:00007FF7875C06ED                 movzx   eax, dil
.text:00007FF7875C06F1                 shr     al, 7
.text:00007FF7875C06F4                 add     dil, dil
.text:00007FF7875C06F7                 movzx   eax, al
.text:00007FF7875C06FA                 xor     cl, r9b
.text:00007FF7875C06FD                 xor     cl, r10b
.text:00007FF7875C0700                 xor     cl, r11b
.text:00007FF7875C0703                 mov     [r14-4], cl
.text:00007FF7875C0707                 imul    ecx, eax, 1Bh
.text:00007FF7875C070A                 xor     cl, dil
.text:00007FF7875C070D                 xor     cl, bl
.text:00007FF7875C070F                 xor     cl, r11b
.text:00007FF7875C0712                 mov     [r14-3], cl
.text:00007FF7875C0716                 sub     r15, 1
.text:00007FF7875C071A                 jnz     loc_7FF7875C0670
.text:00007FF7875C0720                 mov     rax, rsi
.text:00007FF7875C0723                 mov     r8d, 4
.text:00007FF7875C0729                 nop     dword ptr [rax+00000000h]
.text:00007FF7875C0730
.text:00007FF7875C0730 loc_7FF7875C0730:                       ; CODE XREF: sub_7FF7875C0560+1F3↓j
.text:00007FF7875C0730                 mov     edx, 4
.text:00007FF7875C0735                 db      66h, 66h
.text:00007FF7875C0735                 nop     word ptr [rax+rax+00000000h]
.text:00007FF7875C0740
.text:00007FF7875C0740 loc_7FF7875C0740:                       ; CODE XREF: sub_7FF7875C0560+1ED↓j
.text:00007FF7875C0740                 movzx   ecx, byte ptr [rax+rbp]
.text:00007FF7875C0744                 xor     [rax], cl
.text:00007FF7875C0746                 inc     rax
.text:00007FF7875C0749                 sub     rdx, 1
.text:00007FF7875C074D                 jnz     short loc_7FF7875C0740
.text:00007FF7875C074F                 sub     r8, 1
.text:00007FF7875C0753                 jnz     short loc_7FF7875C0730
.text:00007FF7875C0755                 add     rbp, 10h
.text:00007FF7875C0759                 lea     r10, byte_7FF7879DB8A0
.text:00007FF7875C0760                 sub     [rsp+28h+arg_0], 1
.text:00007FF7875C0766                 jnz     loc_7FF7875C05D0
.text:00007FF7875C076C                 mov     r8, rsi
.text:00007FF7875C076F                 lea     r10, byte_7FF7879DB8A0
.text:00007FF7875C0776                 mov     r9d, 4
.text:00007FF7875C077C                 nop     dword ptr [rax+00h]
.text:00007FF7875C0780
.text:00007FF7875C0780 loc_7FF7875C0780:                       ; CODE XREF: sub_7FF7875C0560+24C↓j
.text:00007FF7875C0780                 mov     rcx, r8
.text:00007FF7875C0783                 mov     edx, 4
.text:00007FF7875C0788                 nop     dword ptr [rax+rax+00000000h]
.text:00007FF7875C0790
.text:00007FF7875C0790 loc_7FF7875C0790:                       ; CODE XREF: sub_7FF7875C0560+243↓j
.text:00007FF7875C0790                 movzx   eax, byte ptr [rcx]
.text:00007FF7875C0793                 lea     rcx, [rcx+4]
.text:00007FF7875C0797                 movzx   eax, byte ptr [rax+r10]
.text:00007FF7875C079C                 mov     [rcx-4], al
.text:00007FF7875C079F                 sub     rdx, 1
.text:00007FF7875C07A3                 jnz     short loc_7FF7875C0790
.text:00007FF7875C07A5                 inc     r8
.text:00007FF7875C07A8                 sub     r9, 1
.text:00007FF7875C07AC                 jnz     short loc_7FF7875C0780
.text:00007FF7875C07AE                 movzx   eax, byte ptr [rsi+5]
.text:00007FF7875C07B2                 mov     edx, 4
.text:00007FF7875C07B7                 movzx   ecx, byte ptr [rsi+1]
.text:00007FF7875C07BB                 mov     [rsi+1], al
.text:00007FF7875C07BE                 movzx   eax, byte ptr [rsi+9]
.text:00007FF7875C07C2                 mov     [rsi+5], al
.text:00007FF7875C07C5                 movzx   eax, byte ptr [rsi+0Dh]
.text:00007FF7875C07C9                 mov     [rsi+9], al
.text:00007FF7875C07CC                 movzx   eax, byte ptr [rsi+0Ah]
.text:00007FF7875C07D0                 mov     [rsi+0Dh], cl
.text:00007FF7875C07D3                 movzx   ecx, byte ptr [rsi+2]
.text:00007FF7875C07D7                 mov     [rsi+2], al
.text:00007FF7875C07DA                 movzx   eax, byte ptr [rsi+0Eh]
.text:00007FF7875C07DE                 mov     [rsi+0Ah], cl
.text:00007FF7875C07E1                 movzx   ecx, byte ptr [rsi+6]
.text:00007FF7875C07E5                 mov     [rsi+6], al
.text:00007FF7875C07E8                 movzx   eax, byte ptr [rsi+0Fh]
.text:00007FF7875C07EC                 mov     [rsi+0Eh], cl
.text:00007FF7875C07EF                 movzx   ecx, byte ptr [rsi+3]
.text:00007FF7875C07F3                 mov     [rsi+3], al
.text:00007FF7875C07F6                 movzx   eax, byte ptr [rsi+0Bh]
.text:00007FF7875C07FA                 mov     [rsi+0Fh], al
.text:00007FF7875C07FD                 movzx   eax, byte ptr [rsi+7]
.text:00007FF7875C0801                 mov     [rsi+0Bh], al
.text:00007FF7875C0804                 mov     [rsi+7], cl
.text:00007FF7875C0807                 nop     word ptr [rax+rax+00000000h]
.text:00007FF7875C0810
.text:00007FF7875C0810 loc_7FF7875C0810:                       ; CODE XREF: sub_7FF7875C0560+2D8↓j
.text:00007FF7875C0810                 mov     ecx, 4
.text:00007FF7875C0815                 db      66h, 66h
.text:00007FF7875C0815                 nop     word ptr [rax+rax+00000000h]
.text:00007FF7875C0820
.text:00007FF7875C0820 loc_7FF7875C0820:                       ; CODE XREF: sub_7FF7875C0560+2D2↓j
.text:00007FF7875C0820                 movzx   eax, byte ptr [r12+rsi+0E0h]
.text:00007FF7875C0829                 xor     [rsi], al
.text:00007FF7875C082B                 inc     rsi
.text:00007FF7875C082E                 sub     rcx, 1
.text:00007FF7875C0832                 jnz     short loc_7FF7875C0820
.text:00007FF7875C0834                 sub     rdx, 1
.text:00007FF7875C0838                 jnz     short loc_7FF7875C0810
.text:00007FF7875C083A                 mov     rbx, [rsp+28h+arg_8]
.text:00007FF7875C083F                 mov     rbp, [rsp+28h+arg_10]
.text:00007FF7875C0844                 mov     rsi, [rsp+28h+arg_18]
.text:00007FF7875C0849                 pop     r15
.text:00007FF7875C084B                 pop     r14
.text:00007FF7875C084D                 pop     r13
.text:00007FF7875C084F                 pop     r12
.text:00007FF7875C0851                 pop     rdi
.text:00007FF7875C0852                 retn
.text:00007FF7875C0852 sub_7FF7875C0560 endp