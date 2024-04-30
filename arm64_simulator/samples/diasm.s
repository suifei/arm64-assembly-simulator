__text:0000000100AE0D64             ; void __cdecl -[ :]( *self, SEL, id)
__text:0000000100AE0D64                   ; DATA XREF: __objc_data:00000001043F19D0↓o
__text:0000000100AE0D64
__text:0000000100AE0D64             var_40          = -0x40
__text:0000000100AE0D64             var_38          = -0x38
__text:0000000100AE0D64             var_30          = -0x30
__text:0000000100AE0D64             var_28          = -0x28
__text:0000000100AE0D64             var_20          = -0x20
__text:0000000100AE0D64             var_18          = -0x18
__text:0000000100AE0D64             var_10          = -0x10
__text:0000000100AE0D64             var_8           = -8
__text:0000000100AE0D64             var_s0          =  0
__text:0000000100AE0D64             var_s8          =  8
__text:0000000100AE0D64
__text:0000000100AE0D64 FA 67 BB A9                 STP             X26, X25, [SP,#-0x10+var_40]! ; Store Pair
__text:0000000100AE0D68 F8 5F 01 A9                 STP             X24, X23, [SP,#0x40+var_30] ; Store Pair
__text:0000000100AE0D6C F6 57 02 A9                 STP             X22, X21, [SP,#0x40+var_20] ; Store Pair
__text:0000000100AE0D70 F4 4F 03 A9                 STP             X20, X19, [SP,#0x40+var_10] ; Store Pair
__text:0000000100AE0D74 FD 7B 04 A9                 STP             X29, X30, [SP,#0x40+var_s0] ; Store Pair
__text:0000000100AE0D78 FD 03 01 91                 ADD             X29, SP, #0x40 ; Rd = Op1 + Op2
__text:0000000100AE0D7C F3 03 02 AA                 MOV             X19, X2 ; Rd = Op2
__text:0000000100AE0D80 F4 03 00 AA                 MOV             X20, X0 ; Rd = Op2
__text:0000000100AE0D84 56 AD 99 52                 MOV             W22, #0xF845CD6A
__text:0000000100AE0D84 B6 08 BF 72
__text:0000000100AE0D8C 77 7D 8C 52                 MOV             W23, #0xC13D63EB
__text:0000000100AE0D8C B7 27 B8 72
__text:0000000100AE0D94 98 6D 9E 52                 MOV             W24, #0x9133F36C
__text:0000000100AE0D94 78 26 B2 72
__text:0000000100AE0D9C 59 1F 8A 52                 MOV             W25, #0x229E50FA
__text:0000000100AE0D9C D9 53 A4 72
__text:0000000100AE0DA4 28 C1 01 D0                 ADRP            X8, #selRef_redirects@PAGE ; Address of Page
__text:0000000100AE0DA8 15 5D 46 F9                 LDR             X21, [X8,#selRef_redirects@PAGEOFF] ; Load from Memory
__text:0000000100AE0DAC 1F 03 16 6B                 CMP             W24, W22 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0DB0 E8 A7 9F 1A                 CSET            W8, LT  ; Conditional Set
__text:0000000100AE0DB4 BA D6 01 F0                 ADRL            X26, off_1045B7C20
__text:0000000100AE0DB4 5A 83 30 91
__text:0000000100AE0DBC 49 5B 68 F8                 LDR             X9, [X26,W8,UXTW#3] ; Load from Memory
__text:0000000100AE0DC0 88 6D 9E 52                 MOV             W8, #0x9133F36C
__text:0000000100AE0DC0 68 26 B2 72
__text:0000000100AE0DC8 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0DC8             ; End of function -[ setRedirects:]
__text:0000000100AE0DC8
__text:0000000100AE0DCC
__text:0000000100AE0DCC             ; =============== S U B R O U T I N E =======================================
__text:0000000100AE0DCC
__text:0000000100AE0DCC
__text:0000000100AE0DCC             ; __int64 __usercall sub_100AE0DCC@<X0>(int@<W8>)
__text:0000000100AE0DCC             sub_100AE0DCC                           ; DATA XREF: __data:off_1045B7C20↓o
__text:0000000100AE0DCC 1F 01 19 6B                 CMP             W8, W25 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0DD0 E9 A7 9F 1A                 CSET            W9, LT  ; Conditional Set
__text:0000000100AE0DD4 AA D6 01 F0                 ADRL            X10, off_1045B7C30
__text:0000000100AE0DD4 4A C1 30 91
__text:0000000100AE0DDC 49 59 69 F8                 LDR             X9, [X10,W9,UXTW#3] ; Load from Memory
__text:0000000100AE0DE0 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0DE0             ; End of function sub_100AE0DCC
__text:0000000100AE0DE0
__text:0000000100AE0DE4
__text:0000000100AE0DE4             ; =============== S U B R O U T I N E =======================================
__text:0000000100AE0DE4
__text:0000000100AE0DE4
__text:0000000100AE0DE4             ; __int64 sub_100AE0DE4()
__text:0000000100AE0DE4             sub_100AE0DE4                           ; DATA XREF: __data:off_1045B7C30↓o
__text:0000000100AE0DE4 A9 D6 01 F0                 ADRP            X9, #off_1045B7C48@PAGE ; Address of Page
__text:0000000100AE0DE8 29 25 46 F9                 LDR             X9, [X9,#off_1045B7C48@PAGEOFF] ; Load from Memory
__text:0000000100AE0DEC 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0DF0             ; ---------------------------------------------------------------------------
__text:0000000100AE0DF0
__text:0000000100AE0DF0             loc_100AE0DF0                           ; DATA XREF: __data:00000001045B7C40↓o
__text:0000000100AE0DF0 A9 D6 01 F0                 ADRP            X9, #off_1045B7C50@PAGE ; Address of Page
__text:0000000100AE0DF4 29 29 46 F9                 LDR             X9, [X9,#off_1045B7C50@PAGEOFF] ; Load from Memory
__text:0000000100AE0DF8 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0DFC             ; ---------------------------------------------------------------------------
__text:0000000100AE0DFC
__text:0000000100AE0DFC             loc_100AE0DFC                           ; DATA XREF: __data:00000001045B7C58↓o
__text:0000000100AE0DFC FF 02 16 6B                 CMP             W23, W22 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0E00 E8 A7 9F 1A                 CSET            W8, LT  ; Conditional Set
__text:0000000100AE0E04 49 5B 68 F8                 LDR             X9, [X26,W8,UXTW#3] ; Load from Memory
__text:0000000100AE0E08 68 7D 8C 52                 MOV             W8, #0xC13D63EB
__text:0000000100AE0E08 A8 27 B8 72
__text:0000000100AE0E10 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0E14             ; ---------------------------------------------------------------------------
__text:0000000100AE0E14
__text:0000000100AE0E14             loc_100AE0E14                           ; DATA XREF: __data:00000001045B7C38↓o
__text:0000000100AE0E14 1F 01 16 6B                 CMP             W8, W22 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0E18 E9 17 9F 1A                 CSET            W9, EQ  ; Conditional Set
__text:0000000100AE0E1C AA D6 01 F0                 ADRL            X10, off_1045B7C70
__text:0000000100AE0E1C 4A C1 31 91
__text:0000000100AE0E24 49 59 69 F8                 LDR             X9, [X10,W9,UXTW#3] ; Load from Memory
__text:0000000100AE0E28 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0E2C             ; ---------------------------------------------------------------------------
__text:0000000100AE0E2C
__text:0000000100AE0E2C             loc_100AE0E2C                           ; DATA XREF: __data:00000001045B7C78↓o
__text:0000000100AE0E2C FF 02 16 6B                 CMP             W23, W22 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0E30 E8 A7 9F 1A                 CSET            W8, LT  ; Conditional Set
__text:0000000100AE0E34 49 5B 68 F8                 LDR             X9, [X26,W8,UXTW#3] ; Load from Memory
__text:0000000100AE0E38 68 7D 8C 52                 MOV             W8, #0xC13D63EB
__text:0000000100AE0E38 A8 27 B8 72
__text:0000000100AE0E40 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0E44             ; ---------------------------------------------------------------------------
__text:0000000100AE0E44
__text:0000000100AE0E44             loc_100AE0E44                           ; CODE XREF: sub_100AE0DE4+8↑j
__text:0000000100AE0E44                                                     ; DATA XREF: __data:off_1045B7C48↓o
__text:0000000100AE0E44 1F 01 19 6B                 CMP             W8, W25 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0E48 E9 17 9F 1A                 CSET            W9, EQ  ; Conditional Set
__text:0000000100AE0E4C AA D6 01 F0                 ADRL            X10, off_1045B7C60
__text:0000000100AE0E4C 4A 81 31 91
__text:0000000100AE0E54 49 59 69 F8                 LDR             X9, [X10,W9,UXTW#3] ; Load from Memory
__text:0000000100AE0E58 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0E5C             ; ---------------------------------------------------------------------------
__text:0000000100AE0E5C
__text:0000000100AE0E5C             loc_100AE0E5C                           ; CODE XREF: sub_100AE0DE4+14↑j
__text:0000000100AE0E5C                                                     ; sub_100AE0DE4+74↑j
__text:0000000100AE0E5C                                                     ; DATA XREF: ...
__text:0000000100AE0E5C 1F 01 16 6B                 CMP             W8, W22 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0E60 E9 A7 9F 1A                 CSET            W9, LT  ; Conditional Set
__text:0000000100AE0E64 49 5B 69 F8                 LDR             X9, [X26,W9,UXTW#3] ; Load from Memory
__text:0000000100AE0E68 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0E68             ; End of function sub_100AE0DE4
__text:0000000100AE0E68
__text:0000000100AE0E6C
__text:0000000100AE0E6C             ; =============== S U B R O U T I N E =======================================
__text:0000000100AE0E6C
__text:0000000100AE0E6C
__text:0000000100AE0E6C             ; __int64 __usercall sub_100AE0E6C@<X0>(int@<W8>)
__text:0000000100AE0E6C             sub_100AE0E6C                           ; DATA XREF: __data:00000001045B7C28↓o
__text:0000000100AE0E6C 1F 01 17 6B                 CMP             W8, W23 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0E70 E9 A7 9F 1A                 CSET            W9, LT  ; Conditional Set
__text:0000000100AE0E74 AA D6 01 F0                 ADRL            X10, off_1045B7C80
__text:0000000100AE0E74 4A 01 32 91
__text:0000000100AE0E7C 49 59 69 F8                 LDR             X9, [X10,W9,UXTW#3] ; Load from Memory
__text:0000000100AE0E80 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0E80             ; End of function sub_100AE0E6C
__text:0000000100AE0E80
__text:0000000100AE0E84
__text:0000000100AE0E84             ; =============== S U B R O U T I N E =======================================
__text:0000000100AE0E84
__text:0000000100AE0E84
__text:0000000100AE0E84             ; __int64 sub_100AE0E84()
__text:0000000100AE0E84             sub_100AE0E84                           ; DATA XREF: __data:off_1045B7C80↓o
__text:0000000100AE0E84 E9 17 9F 1A                 CSET            W9, EQ  ; Conditional Set
__text:0000000100AE0E88 AA D6 01 F0                 ADRL            X10, off_1045B7C90
__text:0000000100AE0E88 4A 41 32 91
__text:0000000100AE0E90 49 59 69 F8                 LDR             X9, [X10,W9,UXTW#3] ; Load from Memory
__text:0000000100AE0E94 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0E94             ; End of function sub_100AE0E84
__text:0000000100AE0E94
__text:0000000100AE0E98
__text:0000000100AE0E98             ; =============== S U B R O U T I N E =======================================
__text:0000000100AE0E98
__text:0000000100AE0E98
__text:0000000100AE0E98             ; __int64 sub_100AE0E98()
__text:0000000100AE0E98             sub_100AE0E98                           ; DATA XREF: __data:00000001045B7C98↓o
__text:0000000100AE0E98 3F 03 16 6B                 CMP             W25, W22 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0E9C E8 A7 9F 1A                 CSET            W8, LT  ; Conditional Set
__text:0000000100AE0EA0 49 5B 68 F8                 LDR             X9, [X26,W8,UXTW#3] ; Load from Memory
__text:0000000100AE0EA4 48 1F 8A 52                 MOV             W8, #0x229E50FA
__text:0000000100AE0EA4 C8 53 A4 72
__text:0000000100AE0EAC 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0EAC             ; End of function sub_100AE0E98
__text:0000000100AE0EAC
__text:0000000100AE0EB0
__text:0000000100AE0EB0             ; =============== S U B R O U T I N E =======================================
__text:0000000100AE0EB0
__text:0000000100AE0EB0
__text:0000000100AE0EB0             ; __int64 __usercall sub_100AE0EB0@<X0>(int@<W8>)
__text:0000000100AE0EB0             sub_100AE0EB0                           ; DATA XREF: __data:00000001045B7C88↓o
__text:0000000100AE0EB0 1F 01 18 6B                 CMP             W8, W24 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0EB4 E9 17 9F 1A                 CSET            W9, EQ  ; Conditional Set
__text:0000000100AE0EB8 AA D6 01 F0                 ADRL            X10, off_1045B7CA0
__text:0000000100AE0EB8 4A 81 32 91
__text:0000000100AE0EC0 49 59 69 F8                 LDR             X9, [X10,W9,UXTW#3] ; Load from Memory
__text:0000000100AE0EC4 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0EC4             ; End of function sub_100AE0EB0
__text:0000000100AE0EC4
__text:0000000100AE0EC8
__text:0000000100AE0EC8             ; =============== S U B R O U T I N E =======================================
__text:0000000100AE0EC8
__text:0000000100AE0EC8
__text:0000000100AE0EC8             ; __int64 sub_100AE0EC8()
__text:0000000100AE0EC8             sub_100AE0EC8                           ; DATA XREF: __data:00000001045B7CA8↓o
__text:0000000100AE0EC8 E0 03 14 AA                 MOV             X0, X20 ; object
__text:0000000100AE0ECC E1 03 15 AA                 MOV             X1, X21 ; key
__text:0000000100AE0ED0 E2 03 13 AA                 MOV             X2, X19 ; value
__text:0000000100AE0ED4 63 60 80 52                 MOV             W3, #0x303 ; policy
__text:0000000100AE0ED8 D9 F4 88 94                 BL              _objc_setAssociatedObject ; Branch with Link
__text:0000000100AE0EDC DF 02 16 6B                 CMP             W22, W22 ; Set cond. codes on Op1 - Op2
__text:0000000100AE0EE0 E8 A7 9F 1A                 CSET            W8, LT  ; Conditional Set
__text:0000000100AE0EE4 49 5B 68 F8                 LDR             X9, [X26,W8,UXTW#3] ; Load from Memory
__text:0000000100AE0EE8 48 AD 99 52                 MOV             W8, #0xF845CD6A
__text:0000000100AE0EE8 A8 08 BF 72
__text:0000000100AE0EF0 20 01 1F D6                 BR              X9      ; Branch To Register
__text:0000000100AE0EF0             ; End of function sub_100AE0EC8
__text:0000000100AE0EF0
__text:0000000100AE0EF4
__text:0000000100AE0EF4             ; =============== S U B R O U T I N E =======================================
__text:0000000100AE0EF4
__text:0000000100AE0EF4
__text:0000000100AE0EF4             ; void sub_100AE0EF4()
__text:0000000100AE0EF4             sub_100AE0EF4                           ; DATA XREF: __data:00000001045B7C68↓o
__text:0000000100AE0EF4
__text:0000000100AE0EF4             arg_0           =  0
__text:0000000100AE0EF4             arg_8           =  8
__text:0000000100AE0EF4             arg_10          =  0x10
__text:0000000100AE0EF4             arg_18          =  0x18
__text:0000000100AE0EF4             arg_20          =  0x20
__text:0000000100AE0EF4             arg_28          =  0x28
__text:0000000100AE0EF4             arg_30          =  0x30
__text:0000000100AE0EF4             arg_38          =  0x38
__text:0000000100AE0EF4             arg_40          =  0x40
__text:0000000100AE0EF4             arg_48          =  0x48
__text:0000000100AE0EF4
__text:0000000100AE0EF4 FD 7B 44 A9                 LDP             X29, X30, [SP,#arg_40] ; Load Pair
__text:0000000100AE0EF8 F4 4F 43 A9                 LDP             X20, X19, [SP,#arg_30] ; Load Pair
__text:0000000100AE0EFC F6 57 42 A9                 LDP             X22, X21, [SP,#arg_20] ; Load Pair
__text:0000000100AE0F00 F8 5F 41 A9                 LDP             X24, X23, [SP,#arg_10] ; Load Pair
__text:0000000100AE0F04 FA 67 C5 A8                 LDP             X26, X25, [SP+arg_0],#0x50 ; Load Pair
__text:0000000100AE0F08 C0 03 5F D6                 RET                     ; Return from Subroutine
__text:0000000100AE0F08             ; End of function sub_100AE0EF4
__text:0000000100AE0F08
