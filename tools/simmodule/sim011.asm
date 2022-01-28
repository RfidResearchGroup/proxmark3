; ---------------------------------------------------------------------------
; Proxmark3 RDV4 SIM module firmware
;
; Copyright (C) 2019 Sentinel
;
; This program is free software: you can redistribute it and/or modify it
; under the terms of the GNU Lesser General Public License as published by the
; Free Software Foundation, either version 3 of the License, or (at your
; option) any later version.
;
; This program is distributed in the hope that it will be useful, but WITHOUT
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
; FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
; more details.
;
; You should have received a copy of the GNU Lesser General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>
; ---------------------------------------------------------------------------
                VERS_HI            equ 3
                VERS_LO            equ 11
; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
                SCON_0             equ 098h
                   FE_0            equ 098h.7

                SCON_1             equ 0F8h
                   RI_1            equ 0F8h.0
                   TI_1            equ 0F8h.1
                   FE_1            equ 0F8h.7
                SBUF_1             equ 09Ah
                T3CON              equ 0C4h
                RL3                equ 0C5h
                RH3                equ 0C6h

                P0M1               equ 0B1h
                P0M2               equ 0B2h
                P1M1               equ 0B3h
                P1M2               equ 0B4h
                P3M1               equ 0ACh;
                P3M2               equ 0ADh;

                EIE                equ 09Bh
                EIE1               equ 09Ch

                TA                 equ 0C7h

                RCTRIM0            equ 084h
; ---------------------------------------------------------------------------
                CKCON              equ 08Eh
                CKDIV              equ 095h
; ---------------------------------------------------------------------------
                P1S                equ 0B3h ;Page1
                SFRS               equ 091h ;TA Protection
; ---------------------------------------------------------------------------
                AUXR1              equ 0A2h
; ---------------------------------------------------------------------------
                I2DAT              equ 0BCh;
                I2STAT             equ 0BDh;
                I2CLK              equ 0BEh;
                I2TOC              equ 0BFh;
                I2CON              equ 0C0h;
                  ;                equ I2CON.7;8
                  I2CEN            equ I2CON.6;4
                  STA              equ I2CON.5;2
                  STO              equ I2CON.4;1
                  SI               equ I2CON.3;8
                  AA               equ I2CON.2;4
                  ;                equ I2CON.1;2
                  I2CPX            equ I2CON.0;1


                I2ADDR             equ 0C1h;

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
                pin_TX1            equ P1.6

                pin_TX0            equ P0.6
                pin_RX0            equ P0.7

                pin_SCL            equ P1.3
                pin_SDA            equ P1.4

                pin_RST            equ P1.0
                pin_CLC            equ P1.1
                pin_led            equ P1.2

; ---------------------------------------------------------------------------
; ===========================================================================


                CMD_GENERATE_ATR   equ 01h
                CMD_WRITE_DATA_SIM equ 02h
                CMD_READ_DATA_SIM  equ 03h

                CMD_SET_BAUD_RATE  equ 04h
                CMD_SET_SIM_CLC    equ 05h
                CMD_GET_VERS       equ 06h
                CMD_WRITE_CONFIRM  equ 07h



; ---------------------------------------------------------------------------
; ===========================================================================

                bit_RX0              equ 32.0
                bit_command_receive  equ 32.1
                bit_generate_ATR     equ 32.2
                i2c_write_mode       equ 32.3
                i2c_write_done       equ 32.4
                bit_data_sim_wr      equ 32.5
                bit_length_answer    equ 32.6
                bit_TX0              equ 32.7

                bit_command_buff     equ 33.0
                i2c_write_command    equ 33.1
                i2c_command_done     equ 33.2
                bit_wait_confirm     equ 33.3
                bit_first_ATR        equ 33.4   ;11/03/2019
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                bit_32             equ 32
                bit_33             equ 33
                pointer_RX1        equ 34  ;save SBUF(SIM) to XRAM
                pointer_RX2        equ 35  ;read XRAM to I2C
                pointer_TX         equ 36

                length_send_to_sim equ 37
                length_answer_sim  equ 38
                length_command     equ 39
                time_data_read     equ 40
                time_confirm       equ 41

                buff_command       equ 42
                cmd_command        equ 42
                data_command       equ 43

                STACKKKKK          equ 200
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
; Beginning of the main program
                cseg at 00
                Ljmp    main_start

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
                cseg at 11 ;1302Hz = 4MHZ(Fsys)/12/256
; ---------------------------------------------------------------------------
                jb      time_confirm.7,  $+3+2    ;3
                dec     time_confirm              ;2
; ---------------------------------------------------------------------------
                jb      time_data_read.7,reti_timer0
                djnz    time_data_read,  reti_timer0
                setb    pin_scl
reti_timer0:
                reti


; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
                cseg at 35    ;UART0
                ajmp    jmp_UART0_interrupt

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
                cseg at 51    ;I2C
                ajmp    jmp_i2c_interrupt

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
                cseg at 123   ;UART1
                clr     RI_1
                clr     TI_1
                reti

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
jmp_UART0_interrupt:
                jbc     RI,jmp_byte_RI
                jbc     TI,jmp_byte_TI
                reti
; ---------------------------------------------------------------------------
jmp_byte_RI:
                jnb     bit_first_ATR, jmp_not_collect   ;11/03/2019

                setb    bit_RX0
                jb      i2c_write_done,jmp_not_collect
                PUSH    ACC
                inc     AUXR1           ;DPTR2
                mov     a,SBUF          ;DPTR2
                ;mov     SBUF_1,DPL     ;DPTR2
                mov     DPL,pointer_RX1 ;DPTR2
                mov     DPH,#1          ;DPTR2
                movx    @DPTR,a         ;DPTR2
                inc     pointer_RX1     ;DPTR2
                inc     AUXR1           ;DPTR2
                POP     ACC
                ;09/08/2018
                clr     pin_scl
                mov     time_data_read,#52  ;52/1302Hz = 40mS

                inc     length_answer_sim
jmp_not_collect:
                reti
; ---------------------------------------------------------------------------
jmp_byte_TI:
                setb    bit_TX0
                reti


; ===========================================================================
; ---------------------------------------------------------------------------
jmp_i2c_interrupt:
                PUSH    ACC
                PUSH    PSW
                mov     PSW,#24
                mov     R7,I2STAT
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                cjne    R7,#000h,nextttt00000
                setb    STO
                clr     SI
                jb      STO,$
                ajmp    pop_i2c_psw
nextttt00000:
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                cjne    R7,#060h,nextttt00001    ;START+MY ADDRESS
                clr     pin_led                  ;LED ON

                clr     bit_command_receive
                clr     i2c_write_mode
                clr     bit_data_sim_wr
                clr     bit_length_answer
                clr     bit_command_buff
                clr     i2c_write_command

                ajmp    end_i2c_interrupt
nextttt00001:
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                cjne    R7,#080h,nextttt00002    ;RAM ADRESS

                jb      bit_command_receive,jmp_data_receive
                setb    bit_command_receive

                mov     a,I2DAT
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                cjne    a,#CMD_WRITE_CONFIRM,next_comm001a

                setb    bit_wait_confirm

                sjmp    jmp_WRITEDATASIM
next_comm001a:
; ---------------------------------------------------------------------------
                cjne    a,#CMD_WRITE_DATA_SIM,next_comm001b
                clr     bit_wait_confirm
jmp_WRITEDATASIM:
                mov     length_send_to_sim,#0
                setb    bit_data_sim_wr
                mov     pointer_TX,#0
                ajmp    end_i2c_interrupt
next_comm001b:
; ---------------------------------------------------------------------------
                cjne    a,#CMD_GENERATE_ATR,next_comm002
                setb    bit_generate_ATR
                ;Prepare to answer
                mov     length_answer_sim,#0
                mov     pointer_RX1,#0
                mov     pointer_RX2,#0
                ajmp    end_i2c_interrupt
next_comm002:
; ---------------------------------------------------------------------------
                cjne    a,#CMD_GET_VERS,next_comm003
                ajmp    ANSWER_VERS
next_comm003:
; ---------------------------------------------------------------------------
                cjne    a,#CMD_SET_BAUD_RATE,next_comm004
                mov     R0,#data_command
                mov     length_command,#0
                mov     cmd_command,#CMD_SET_BAUD_RATE
                setb    i2c_write_command
                ajmp    end_i2c_interrupt
next_comm004:
; ---------------------------------------------------------------------------
                cjne    a,#CMD_SET_SIM_CLC,next_comm005
                mov     R0,#data_command
                mov     length_command,#0
                mov     cmd_command,#CMD_SET_SIM_CLC
                setb    i2c_write_command
                ajmp    end_i2c_interrupt
next_comm005:
; ---------------------------------------------------------------------------
                ajmp    end_i2c_interrupt
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
jmp_data_receive:
                ;What receive ? Data to SIM/Command to bridge
                jb      bit_data_sim_wr,  jmp_data_sim_receive
                jb      i2c_write_command,jmp_comm_bridge_receive
                ajmp    end_i2c_interrupt
; ---------------------------------------------------------------------------
jmp_comm_bridge_receive:
                mov     @R0,I2DAT
                inc     R0
                inc     length_command
                ajmp    end_i2c_interrupt
; ---------------------------------------------------------------------------
jmp_data_sim_receive:

                setb    i2c_write_mode

                inc     AUXR1          ;DPTR2
                mov     a,I2DAT        ;DPTR2
                mov     DPL,pointer_TX ;DPTR2
                mov     DPH,#0         ;DPTR2
                movx    @DPTR,a        ;DPTR2
                inc     pointer_TX     ;DPTR2
                inc     AUXR1          ;DPTR2

                inc     length_send_to_sim
                ajmp    end_i2c_interrupt
nextttt00002:
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                cjne    R7,#0A0h,nextttt00003    ;STOP
                setb    pin_led                  ;LED OFF

                ;Command finish ?
                jnb     i2c_write_command,jmp_not_command
                clr     i2c_write_command
                setb    i2c_command_done
jmp_not_command:

                ;data to SIM finish ?
                jnb     i2c_write_mode,end_i2c_interrupt
                clr     i2c_write_mode

                setb    i2c_write_done
                ;Prepare to answer
                mov     length_answer_sim,#0
                mov     pointer_RX1,#0
                mov     pointer_RX2,#0

                ajmp    end_i2c_interrupt
nextttt00003:
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                cjne    R7,#0A8h,nextttt00004
                sjmp    read_byte_I2C
nextttt00004:
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                cjne    R7,#0B8h,nextttt00005
read_byte_I2C:
                jnb     bit_command_buff,jmp_not_comm_buff2
                mov     I2DAT,@R0
                inc     R0
                ajmp    end_i2c_interrupt

jmp_not_comm_buff2:
                jb      bit_length_answer,read_byte_APROM
                setb    bit_length_answer

                mov     I2DAT,length_answer_sim
                ajmp    end_i2c_interrupt
read_byte_APROM:
                inc     AUXR1           ;DPTR2
                mov     DPL,pointer_RX2 ;DPTR2
                mov     DPH,#1          ;DPTR2
                movx    a,@DPTR         ;DPTR2
                mov     I2DAT,a         ;DPTR2
                inc     pointer_RX2     ;DPTR2
                inc     AUXR1           ;DPTR2
nextttt00005:
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
end_i2c_interrupt:
                clr     STA
                clr     STO
                setb    AA
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
pop_i2c_psw:
                POP     PSW
                POP     ACC
                clr     SI
                reti


; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
ANSWER_VERS:
                mov     R0,#data_command
                mov     cmd_command,#CMD_GET_VERS
                mov     (data_command+0),#2
                mov     (data_command+1),#VERS_HI
                mov     (data_command+2),#VERS_LO
                setb    bit_command_buff
                ajmp    end_i2c_interrupt


; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
; %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
main_start:
                mov     SP,#STACKKKKK
; ---------------------------------------------------------------------------
                ;0-bidirect  1-push pull   0-input only  1-open drain
                ;0           0             1             1
; ---------------------------------------------------------------------------
                mov     P0M2,#01000000b  ;Р0
                mov     P0M1,#11111111b  ;P1.6-Tx0 SIM;
                ;
                mov     P1M2,#01011111b  ;Р1
                mov     P1M1,#10111000b  ;P1.6-Tx1 DEBUG; P1.4,P1.3 - I2C;

                mov     P3M2,#00000000b  ;P3
                mov     P3M1,#11111111b  ;
; ---------------------------------------------------------------------------
                mov     TMOD, #22h
                mov     TH0,  #0      ;14400hz
                mov     TH1,  #0E9h   ;UART0 10800 Bit/sec
                mov     TCON, #55h
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                mov     TA,#0AAh
                mov     TA,#055h
                orl     SFRS,#00000001b

                mov     P1S, #00010000b  ;P1.4 trigger schmiddt

                mov     TA,#0AAh
                mov     TA,#055h
                anl     SFRS,#11111110b
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                ;-------  CONFIG I2C  ---------
                mov     I2CON, #44h        ;set AA, set I2C enable
                setb    pin_sda
                setb    pin_scl
                mov     I2ADDR,#0C0h
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                ;mov     SCON,  #050h     ;UART0 8bit
                mov     SCON,  #0D0h     ;UART0 9bit
                ;mov     PCON,  #11000000b;FE_0 enable
                mov     PCON,  #10000000b;FE_0 disable
; ---------------------------------------------------------------------------
                mov     SCON_1,#050h     ;UART1
                ;mov     T3CON, #01101000b;FE_1 enable TIMER3 UART0 BAUD
                ;mov     T3CON, #00101000b;FE_1 disable TIMER3 UART0 BAUD
                mov      T3CON, #00001000b;FE_1 disable TIMER1 UART0 BAUD
                ;mov     RL3,#0E9h        ;10800/21600
                ;mov     RH3,#0FFh
; ---------------------------------------------------------------------------
                ;UART1
                mov     RL3,#0F7h         ;27777/55556
                mov     RH3,#0FFh
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                mov     CKDIV,#2      ;Fsys=4.00MHZ
                ;mov     CKDIV,#1      ;Fsys=8.00MHZ
; ---------------------------------------------------------------------------
                mov     bit_32,#0
                mov     bit_33,#0
                setb    time_data_read.7
; ---------------------------------------------------------------------------
                ;orl     CKCON,#00000010b  ;ENABLE CLC TIMER1 Fsys/12
                orl    CKCON,#00010010b  ;ENABLE CLC TIMER1 Fsys
; ---------------------------------------------------------------------------
                ;mov     a,RCTRIM0
                ;add     a,#31
                ;mov     TA,#0AAh
                ;mov     TA,#055h
                ;mov     RCTRIM0,a
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                acall   clr_buffer
; ---------------------------------------------------------------------------
                mov     EIE, #00000001b    ;I2C Interrupt
                ;mov     IE,  #10010000b    ;EA, SERIAL0
                mov     IE,  #10010010b    ;EA, SERIAL0, TIMER0
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
main_loop:
                acall   control_ATR
                acall   control_send_to_sim
                acall   control_command
                sjmp    main_loop

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
control_command:
                jbc     i2c_command_done,$+3+1    ;3
                ret                               ;1
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                ;Control Length command=1
                mov     a,length_command
                cjne    a,#1,next_commandEND  ;error length_command != 1
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                mov     a,cmd_command
                cjne    a,#CMD_SET_BAUD_RATE,next_command001
                mov     TH1,data_command   ;Timer1 HIGH byte
                ret
next_command001:
; ---------------------------------------------------------------------------
                cjne    a,#CMD_SET_SIM_CLC,  next_command002
                mov     CKDIV,data_command ;Fsys  DIV
                ret
next_command002:
; ---------------------------------------------------------------------------
next_commandEND:
                ret

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
control_send_to_sim:
                jb      i2c_write_done,$+3+1    ;3
                ret                             ;1
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                jbc     bit_wait_confirm,jmp_wait_confirm
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                mov     DPTR,#0000
looop_send:
                movx    a,@DPTR
                inc     DPTR
                acall   for_coooooom0
                djnz    length_send_to_sim,looop_send
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                jnb     bit_RX0,$
                clr     i2c_write_done
                ret


; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
jmp_wait_confirm:
                mov     DPTR,#0001
                movx    a,@DPTR
                mov     R3,a
                mov     R4,#5
; ---------------------------------------------------------------------------
                mov     DPTR,#0000
looop_seend:
                movx    a,@DPTR
                inc     DPTR
                acall   for_coooooom0
                djnz    R4,jmp_not_5byte

                jnb     bit_RX0,$
                clr     bit_RX0
                ;18/12/2018
                mov     time_confirm,#65  ;New timeout 50mS
looop_waitconf:
                jb      time_confirm.7,jmp_no_answer
                jnb     bit_RX0,looop_waitconf

                ;clr     pin_scl   ;TEST PULSE!
                mov     a,SBUF
                xrl     a,R3
                ;setb    pin_scl   ;TEST PULSE!

                jnz     jmp_no_correct_answer   ;18/12/2018

                ;pause  for next byte 17/12/2018
                mov     R7,#0
                djnz    R7,$   ;~260mkSec
                djnz    R7,$   ;~260mkSec
                djnz    R7,$   ;~260mkSec

jmp_not_5byte:
                djnz    length_send_to_sim,looop_seend
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
                jnb     bit_RX0,$
                clr     bit_RX0
jmp_no_answer:
                clr     i2c_write_done
                ret

; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
;18/12/2018
jmp_no_correct_answer:
                clr     EA
                clr     i2c_write_done
                mov     a,SBUF
                mov     DPL,pointer_RX1
                mov     DPH,#1
                movx    @DPTR,a
                inc     pointer_RX1
                clr     pin_scl
                mov     time_data_read,#52  ;52/1302Hz = 40mS
                inc     length_answer_sim
                setb    EA
                ret



; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
control_ATR:
                jbc     bit_generate_ATR,$+3+1   ;3
                ret                              ;1
; ---------------------------------------------------------------------------
                clr     pin_RST
                ;acall   clr_buffer
                ; Add rezet pause  17/12/2018

                mov     R6,#200
looop_pause50mS:
                djnz    R7,$     ;~260mkSec
                djnz    R6,looop_pause50mS

                ;Prepare to answer 11/03/2019
                acall   clr_buffer
                mov     length_answer_sim,#0
                mov     pointer_RX1,#0
                mov     pointer_RX2,#0
                setb    bit_first_ATR
                setb    pin_RST
                ret

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
for_coooooom0:
                clr     bit_RX0
                mov     c,P
                mov     TB8,c         ;9bit parity
                mov     SBUF,a
                jnb     bit_TX0,$
                clr     bit_TX0
                mov     R7,#100
                djnz    R7,$
                ret

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
clr_buffer:
                mov     DPTR,#0256     ;Receive SIM buffer
                mov     R7,#255
                clr     a
looop_clr_bufff:
                movx    @DPTR,a
                inc     DPTR
                djnz    R7,looop_clr_bufff
                ret

; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------
;for_coooooom1:
;                mov     SBUF_1,a
;                jnb     TI_1,$
;                clr     TI_1
;                ret
;
; ---------------------------------------------------------------------------
; ===========================================================================
; ---------------------------------------------------------------------------

end.
