module fpga_top (
    input ck_1356meg,
    input ck_1356meg_b,        // B is for close range wiring
    input spi_sck,
    input pck0,
    input spi_ncs,
    input [9:0] adc_d,
    input cross_lo,
    input spi_mosi,
    input ssp_dout,
    input module_sel,         // 选择模块，1=HF，0=LF
    
    output ssp_din,
    output ssp_frame,
    output ssp_clk,
    output adc_clk,
    output spi_miso,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe4,
    output dbg1,
    output dbg2,
    output dbgled,

    output clk_gate,         //门控输出，控制切断外部13.56m
    output pwr_pwm,          //升压器输出，pwm控制升压电压
    output pan_en,           //模拟供电使能
    output pdp_en            //升压器使能
);
    
    wire ce_lf = ~module_sel; //高启用，低重置
    wire ce_hf = module_sel; //高启用，低重置
    //-----------------------------------------GATE-------------------------
    //门控使能信号同步到输入时钟域，避免亚稳态
    reg gate_en_sync1, gate_en_sync2;
    always @(posedge ck_1356meg) begin
        gate_en_sync1 <= gate_en;
        gate_en_sync2 <= gate_en_sync1;
    end
    
    assign clk_gate = ~gate_en_sync2;//这里取反是因为外部门控是低有效的
    //-----------------------------------------PWM--------------------------
    
    Gowin_rPLL pwr_pwm_pll(
        .clkout(pwr_pwm_pll_clko), //output clkout
        .clkin(ck_1356meg) //input clkin
    );

    wire [11:0] pwm_duty_lf;   // LF 模块的 PWM 占空比输出
    wire [11:0] pwm_duty_hf;   // HF 模块的 PWM 占空比输出

    wire [11:0] pwm_duty;      // PWM占空比，实际上是高电平长度，和4096做比例
    reg [11:0] pwm_cnt= 12'h0;

    always @(posedge pwr_pwm_pll_clko) pwm_cnt <= pwm_cnt + 1'b1;  //计数器
    assign pwr_pwm = (pwm_cnt > pwm_duty);  //pwm输出

    assign pan_en = 1'b1;
    assign pdp_en = 1'b1;

    assign pwr_hi = 1'bZ;   //使用外部门控时禁用PWRHI,由于是并联的，需要高阻
    assign dbgled = 1'b1;
    assign dbg2   = 1'bZ;  // 未使用

    fpga_lf uut_lf (
        .pck0(pck0),

        .spck(spi_sck),
        .ncs(spi_ncs),

        .adc_d(adc_d[9:2]),
        .cross_lo(cross_lo),
        .mosi(spi_mosi),
        .ssp_dout(ssp_dout),
        .ce(ce_lf),
        
        .ssp_din(ssp_din_lf),
        .ssp_frame(ssp_frame_lf),
        .ssp_clk(ssp_clk_lf),
        .adc_clk(adc_clk_lf),
        .miso(miso_lf),
        .pwr_lo(pwr_lo_lf),
        .pwr_oe1(pwr_oe1_lf),
        .pwr_oe2(pwr_oe2_lf),
        .pwr_oe4(pwr_oe4_lf),
        .dbg(dbg_lf),

        .pwm_duty(pwm_duty_lf)
    );

    fpga_hf uut_hf (
        .ck_1356meg(ck_1356meg),

        .spck(spi_sck),
        .ncs(spi_ncs),

        .adc_d(adc_d[9:2]),
        .mosi(spi_mosi),
        .ssp_dout(ssp_dout),
        .ce(ce_hf),
        
        .ssp_din(ssp_din_hf),
        .ssp_frame(ssp_frame_hf),
        .ssp_clk(ssp_clk_hf),
        .adc_clk(adc_clk_hf),
        .miso(miso_hf),
        .pwr_lo(pwr_lo_hf),
        .pwr_hi(gate_en),
        .pwr_oe1(pwr_oe1_hf),
        .pwr_oe2(pwr_oe2_hf),
        .pwr_oe4(pwr_oe4_hf),
        .dbg(dbg_hf),

        .pwm_duty(pwm_duty_hf)
    );

    assign ssp_din   = ~module_sel ? ssp_din_lf   : ssp_din_hf;
    assign ssp_frame = ~module_sel ? ssp_frame_lf : ssp_frame_hf;
    assign ssp_clk   = ~module_sel ? ssp_clk_lf   : ssp_clk_hf;
    assign adc_clk   = ~module_sel ? adc_clk_lf   : adc_clk_hf;
    assign spi_miso  = ~module_sel ? miso_lf      : miso_hf;
    assign pwr_lo    = ~module_sel ? pwr_lo_lf    : pwr_lo_hf;
    //assign pwr_hi    = ~module_sel ? pwr_hi_lf    : pwr_hi_hf;
    assign pwr_oe1   = ~module_sel ? pwr_oe1_lf   : pwr_oe1_hf;
    assign pwr_oe2   = ~module_sel ? pwr_oe2_lf   : pwr_oe2_hf;
    assign pwr_oe4   = ~module_sel ? pwr_oe4_lf   : pwr_oe4_hf;
    assign dbg1      = ~module_sel ? dbg_lf       : dbg_hf;
    assign pwm_duty  = ~module_sel ? pwm_duty_lf  : pwm_duty_hf;

endmodule