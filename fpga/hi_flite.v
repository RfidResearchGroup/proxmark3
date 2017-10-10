// Satsuoni, October 2017,  Added FeliCa support
//
//this code demodulates and modulates signal as described in ISO/IEC 18092.  That includes packets used for Felica, NFC Tag 3, etc. (which do overlap)
//simple envelope following algorithm is used (modification of fail0verflow LF one) is used to combat some nasty aliasing effect with testing phone (envelope looked like sine wave) 
// only 212 kbps (fc/64) for now 414 is relatively straightforward... 
// modulation waits for 

//market sprocket -doesn't really mean anything ;) 
`define SNIFFER	3'b000
`define TAGSIM_LISTEN	3'b001 //same as SNIFFER, really. demod does not distinguish tag from reader
`define TAGSIM_MODULATE	3'b010
`define TAGSIM_MOD_NODELAY	3'b011 //not implemented yet. for use with commands other than polling, which might require different timing, as per Felica standard

module hi_flite(
    pck0, ck_1356meg, ck_1356megb,
    pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
    adc_d, adc_clk,
    ssp_frame, ssp_din, ssp_dout, ssp_clk,
    cross_hi, cross_lo,
    dbg,
    mod_type // maybe used
);
    input pck0, ck_1356meg, ck_1356megb;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    input cross_hi, cross_lo;
    output dbg;
    input [2:0] mod_type; // maybe used.
assign dbg=0;

// Most off, oe4 for modulation; No reader emulation (would presumably just require switching power on, but I am not sure) 
assign pwr_hi  = 1'b0;
assign pwr_lo  = 1'b0;
assign pwr_oe1 = 1'b0;
assign pwr_oe2 = 1'b0;
assign pwr_oe3 = 1'b0;


//512x64/fc  -wait before ts0, 32768 ticks
//tslot: 256*64/fc

assign adc_clk = ck_1356meg;


///heuristic values for initial thresholds. seem to work OK
`define imin 70//(13'd256)
`define imax 180//(-13'd256)
`define ithrmin 91//-13'd8
`define ithrmax 160// 13'd8


//minimum values and corresponding thresholds
reg  [8:0] curmin=`imin;

reg [8:0] curminthres=`ithrmin; 

reg [8:0] curmaxthres=`ithrmax;
reg [8:0] curmax=`imax;


//signal state, 1-not modulated, 0 -modulated
reg after_hysteresis = 1'b1;

//state machine for envelope tracking
reg [1:0] state=1'd0;


//lower edge detected, trying to  detect first bit of SYNC (b24d, 1011001001001101)
reg try_sync=1'b0;

//detected first sync bit, phase frozen
reg did_sync=0;


`define bithalf_212 32 //half-bit length for 212 kbit
`define bitlen_212 64 //full-bit length for 212 kbit
`define bitmlen_212 63 //bit transition edge
`define bitmhalf_212 31 //mod flip


//ssp clock and current values
reg ssp_clk;
reg ssp_frame;
reg curbit=1'b0;

reg [7:0] fccount=8'd0; // in-bit tick counter. Counts carrier cycles from the first lower edge detected, reset on every manchester bit detected

reg [7:0] tsinceedge=8'd0;// ticks from last edge,  desync if the valye is too large

reg zero=1'b0; // Manchester first halfbit low second high corresponds to this value. It has been known to change. SYNC is used to set it

//ssp counter for transfer and framing
reg [8:0] ssp_cnt=9'd0;

always @(posedge adc_clk)
     ssp_cnt <= (ssp_cnt + 1);


reg getting_arm_data=1'b0; 


reg  [47:0] delayline=48'd0; //48-bit preamble delay line. Just push the data into it starting from first  SYNC (1) bit coming from ARM Made this long to keep all ARM data received during preamble
reg  [5:0] delay_read_ptr=6'd0; // this is supposed to count ARM delay in the buffer. 
reg preamble=0; // whether we are sending preamble

    
  
always @(negedge adc_clk)
begin
     //count fc/64 - transfer bits to ARM at the rate they are received
     if(ssp_cnt[5:0] == 6'b000000)
        begin
			ssp_clk <= 1'b1;
            ssp_din <= curbit;  
            
            //sample ssp_dout?
            if(mod_type==`TAGSIM_MODULATE||mod_type==`TAGSIM_MOD_NODELAY)
            begin
             delayline<={delayline[46:0],ssp_dout};
             if ((~getting_arm_data) && ssp_dout)
             begin
             getting_arm_data <=1'b1;
             delay_read_ptr<=delay_read_ptr+1;
             end
             else
             begin
               if (getting_arm_data & preamble)
                begin
                delay_read_ptr<=delay_read_ptr+1;
                end
             end
            end
            else
            begin
              getting_arm_data <=1'b0;
              delay_read_ptr<=6'd0;
            end
                           
        end
		if(ssp_cnt[5:0] == 6'b100000)
			ssp_clk <= 1'b0;
    //create frame pulses. TBH, I still don't know what they do exactly, but they are crucial for ARM->FPGA transfer. If the frame is in the beginning of the byte, transfer slows to a crawl for some reason
    // took me a day to figure THAT out.         
       if(ssp_cnt[8:0] == 9'd31)
        begin
			ssp_frame <= 1'b1;    
        end
         if(ssp_cnt[8:0] == 9'b1011111)
        begin
			ssp_frame <= 1'b0;    
        end
end




//send current bit (detected in SNIFF mode or the one being modulated in MOD mode, 0 otherwise)
reg ssp_din;    
  
  

//previous signal value, mostly to detect SYNC
reg prv =1'b1;


reg[7:0] mid=8'd128; //for simple error correction in mod/demod detection, use maximum of modded/demodded in given interval. Maybe 1 bit is extra? but better safe than sorry. 

//modulated coil. set to 1 to modulate low, 0 to keep signal high
reg mod_sig_coil=1'b0;

// set TAGSIM__MODULATE on ARM if we want to write... (frame would get lost if done mid-frame...)
// start sending over 1s on ssp->arm when we start sending preamble

reg counting_desync=1'b0; // are we counting bits since last frame? 
reg sending=1'b0;  // are we actively modulating? 
reg [11:0] bit_counts=12'd0;///for timeslots... only support ts=0 for now, at 212 speed  -512 fullbits from end of frame. One hopes.                   


always @(negedge adc_clk) //every data ping? 
begin
  //envelope follow code...          
  ////////////   
  if ((mod_type==`SNIFFER )||(mod_type==`TAGSIM_LISTEN))
  begin     
      if (adc_d>curmaxthres) //rising edge
       begin
        case (state)
         0: begin
            curmax <= adc_d>155? adc_d :155;
            state <= 2;
            end
         1: begin
            curminthres <= ( (curmin>>1)+(curmin>>2)+(curmin>>4)+(curmax>>3)+(curmax>>4)); //threshold: 0.1875 max + 0.8125 min
            curmaxthres <= ( (curmax>>1)+(curmax>>2)+(curmax>>4)+(curmin>>3)+(curmin>>4));
            curmax <= adc_d>155? adc_d :155; // to hopefully prevent overflow from spikes going up to 255
            state <= 2;
            end
         2: begin
            if (adc_d>curmax)
               curmax <= adc_d;
            end  
         default:
            begin
            end        
        endcase
        after_hysteresis <=1'b1;
        if(try_sync)
          tsinceedge<=0;
       end
      else if (adc_d<curminthres) //falling edge
        begin 
          case (state)
            0: begin
               curmin <=adc_d<96? adc_d :96; 
               state <=1;
               end
            1: begin
               if (adc_d<curmin)
                 curmin <= adc_d; 
               end
            2: begin
                curminthres <= ( (curmin>>1)+(curmin>>2)+(curmin>>4)+(curmax>>3)+(curmax>>4));
                curmaxthres <= ( (curmax>>1)+(curmax>>2)+(curmax>>4)+(curmin>>3)+(curmin>>4));
                curmin <=adc_d<96? adc_d :96;
                state <=1;       
               end 
            default:
              begin
              end              
          endcase   
              after_hysteresis <=0;
          if (~try_sync ) //begin modulation, lower edge... 
             begin
             try_sync <=1;
             counting_desync<=1'b0;
             fccount <= 1;
             did_sync<=0;
             curbit<=0;
             mid <=8'd127;
             tsinceedge<=0;
             prv <=1;
             end  
           else
           begin
           tsinceedge<=0;
           end
         end
        else //stable state, low or high
         begin
            curminthres <= ( (curmin>>1)+(curmin>>2)+(curmin>>4)+(curmax>>3)+(curmax>>4));
            curmaxthres <= ( (curmax>>1)+(curmax>>2)+(curmax>>4)+(curmin>>3)+(curmin>>4));
            state <=0;
            
             if (try_sync )
              begin
               if (tsinceedge>=(128))
                  begin
                  //we might need to start counting... assuming ARM wants to reply to the frame. 
                  counting_desync<=1'b1;
                  bit_counts<=1;// i think? 128 is about 2 bits passed... but 1 also works
                  try_sync<=0;
                  did_sync<=0;//desync
                  curmin <=`imin; //reset envelope
                  curmax <=`imax;
                  curminthres <=`ithrmin;
                  curmaxthres <=`ithrmax; 
                  prv <=1;
                  tsinceedge <=0;
                  after_hysteresis <=1'b1;
                  curbit <=0;
                  mid <=8'd128;
                  end
               else
                tsinceedge<=(tsinceedge+1);
              end
         end 
        
        //move the counter to the outside...
        if (adc_d>=curminthres||try_sync) 
        if(fccount==`bitmlen_212)
        begin
         fccount<=0;
         if (counting_desync)
          begin
           
           if(bit_counts>768) // should be over ts0 now, without ARM interference... stop counting...
               begin 
               bit_counts<=0;
               counting_desync<=0;
               end
            else
               bit_counts<=bit_counts+1; 
          end 
        end
        else
        begin 
          fccount<=fccount+1;
        end
        
        if (try_sync && tsinceedge<128)
            begin
            //detect bits in their middle ssp sampling is in sync, so it would sample all bits in order
            if (fccount==`bithalf_212)
              begin
                if ((~did_sync) && ((prv==1&&(mid>128))||(prv==0&&(mid<=128))))
                  begin 
                        //sync the Zero, and set curbit roperly
                        did_sync <=1'b1;
                        zero <= ~prv;// 1-prv
                        curbit <=1;
                  end   
                else 
                    curbit <= (mid>128) ? (~zero):zero;
                    
                 prv <=(mid>128) ?1:0;  
                  
                 if(adc_d>curmaxthres)   
                  mid <=8'd129;
                 else if (adc_d<curminthres) 
                    mid <=8'd127;
                 else 
                  begin
                   if (after_hysteresis)
                   begin
                   mid <=8'd129;
                   end
                   else
                   begin
                   mid<=8'd127;
                   end
                  end
                    
               end
             else  
              begin  
                if (fccount==`bitmlen_212)
                  begin
                  // fccount <=0;
                   prv <=(mid>128)?1:0; 
                   mid <=128;
                  end
                else
                 begin
                // minimum-maximum calc
                  if(adc_d>curmaxthres)   
                     mid <=mid+1;
                   else if (adc_d<curminthres) 
                    mid <=mid-1;
                   else 
                    begin
                     if (after_hysteresis)
                       begin
                       mid <=mid+1;
                       end
                       else
                       begin
                       mid<=mid-1;
                       end
                    end 
                 end
              end  
            end 
           else
           begin
            end       
       sending <=0;     
       
    end //listen mode end
    else
    begin //sim mode start
    //not sure how precise do the time slots have to be... is anything within Ts ok? 
    //keep counting until  576, just in case
     if(fccount==`bitmlen_212)
        begin
      if (bit_counts==512) //
           curbit<=1;
           else
           begin
           if(bit_counts>512)
            curbit<=mod_sig_coil;//delayline[delay_read_ptr];//bit_counts[0];
           else 
            curbit<=0;
           end
   
         fccount<=0;
         if (bit_counts<=576) //we don't need to count after that... 
          begin          
            bit_counts<=bit_counts+1;
            if (bit_counts== 512) //should start sending from next tick... i think?
            begin
            sending <=1;
            mod_sig_coil <=1;//modulate... down? 
            preamble<=1;
            end
            else
            if  (bit_counts== 559)
            begin
               preamble<=0;
            end
          end 
         if (sending)
         begin //need next bit
             if(preamble)
              mod_sig_coil<=1;
             else
              mod_sig_coil<=~delayline[delay_read_ptr]; 
         end
        end
        else
        begin 
          fccount<=fccount+1;
          
          if ((fccount==`bitmhalf_212)&&(sending)) //flip modulation mid-bit
          begin
           mod_sig_coil<=~mod_sig_coil;//flip
          end
        end
    end   //sim mode end     
     
end

assign pwr_oe4 =  mod_sig_coil  & (mod_type == `TAGSIM_MODULATE)&sending;

endmodule
