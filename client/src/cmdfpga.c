#include "fileutils.h"
#include "cmdparser.h"      // command_t
#include "cliparser.h"
#include "comms.h"
#include "cmdfpga.h"
#include "ui.h"
#include "util_posix.h" // msclock

static int CmdHelp(const char *Cmd);

static int CmdConfigFpga(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw fpga config ",
                  "Read the bin file and write it to the fpga [sram|flash]",
                  "hw fpga config -s -f myfile                    -> config fpga sram by bin file\n"
                  "hw fpga config -f myfile                       -> config fpga flash by bin file\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s", "sram", "config to sram, or config to flash"),
        arg_str0("f", "file", "<fn>", "save to file, not suffix include"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // config to sram or flash by -s option
    bool sram_mode = arg_get_lit(ctx, 1);

    // check for -file option first to determine the output mode
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    if ((! sram_mode) && (! IfFpgaFlash())) {
        PrintAndLogEx(WARNING, "This device does not support FPGA flash configuration");
        return PM3_ENOTIMPL;
    }

    // Check if file name is provided
    if (fnlen == 0) {
        PrintAndLogEx(WARNING, "No file specified");
        return PM3_EINVARG;
    }

    // Load the file content into data buffer
    uint8_t *data = NULL;
    size_t datalen = 0;
    int res = loadFile_safe(filename, ".bin", (void **)&data, &datalen);
    if (res != PM3_SUCCESS) {
        free(data);
        return PM3_EFILE;
    }

    struct {
        uint8_t sram_mode;
        uint32_t file_length;
    } PACKED params;
    params.sram_mode = sram_mode;
    params.file_length = datalen;

    PacketResponseNG resp;
    PrintAndLogEx(INFO, "Starting FPGA configuration in " _YELLOW_("%s"), sram_mode ? "SRAM" : "Flash");

    // Start fpga config by mode
    uint64_t t_start = msclock();
    SendCommandNG(CMD_FPGA_BITSTREAM_CONFIG_START, (uint8_t *)&params, sizeof(params));
    // Wait for response before sending data
    if (WaitForResponseTimeout(CMD_FPGA_BITSTREAM_CONFIG_START, &resp, 15000) == false) {
        PrintAndLogEx(WARNING, "start config for fpga timeout while waiting for reply");
        free(data);
        return PM3_ETIMEOUT;
    }
    if (resp.status == PM3_ENOTIMPL) {
        PrintAndLogEx(ERR, "Feature not implemented");
        free(data);
        return resp.status;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to start FPGA configuration: %d", resp.status);
        free(data);
        return resp.status;
    }

    // Start to send data in chunks
    size_t offset = 0;
    while (offset < datalen) {
        size_t chunk_size = (datalen - offset) > g_conn.max_cmd_data_size ? g_conn.max_cmd_data_size : (datalen - offset);
        SendCommandNG(CMD_FPGA_BITSTREAM_CONFIG_WRITE, data + offset, chunk_size);
        // Wait for response before sending next chunk
        if (WaitForResponseTimeout(CMD_FPGA_BITSTREAM_CONFIG_WRITE, &resp, 5000) == false) {
            PrintAndLogEx(WARNING, "transfer data for fpga timeout while waiting for reply");
            free(data);
            return PM3_ETIMEOUT;
        }
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to transfer FPGA configuration data: %d", resp.status);
            free(data);
            return resp.status;
        }
        offset += chunk_size;
        // Print progress
        PrintAndLogEx(INFO, "Sent "_YELLOW_("%zu")" bytes, progress: "_YELLOW_("%.2f%%"), chunk_size, (offset / (float)datalen) * 100);
    }

    PrintAndLogEx(SUCCESS, "FPGA configuration transfer complete!");

    // Stop fpga config
    SendCommandNG(CMD_FPGA_BITSTREAM_CONFIG_FINISH, NULL, 0);
    if (WaitForResponseTimeout(CMD_FPGA_BITSTREAM_CONFIG_FINISH, &resp, 5000) == false) {
        PrintAndLogEx(WARNING, "stop config for fpga timeout while waiting for reply");
        free(data);
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to finish FPGA configuration: %d", resp.status);
        free(data);
        return resp.status;
    }

    uint64_t elapsed_ms = msclock() - t_start;
    PrintAndLogEx(SUCCESS, "FPGA configuration successfully! Total time: " _YELLOW_("%.2f") " s (" _YELLOW_("%.0f") " ms)",
                  (float)elapsed_ms / 1000.0f, (float)elapsed_ms);
    free(data);
    return PM3_SUCCESS;
}

static int CmdFpgaSetPowerPWM(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw fpga pwrpwm ",
                  "Set the proportion of low levels of PWM output from FPGA for controlling driver voltage.",
                  "hw fpga pwrpwm -c 1000                    -> Set pwm low-level count to 1000 for HF driver power.\n"
                  "hw fpga pwrpwm -c 1000 -l                 -> Set pwm low-level count to 1000 for LF driver power.\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("l", "lf", "Set the driver voltage for LF. When not specified as LF, default setting for HF."),
        arg_int0("c", "count", "<int>", "PWM output low level counting used to control the voltage of the driver. "
        "The larger the value, the higher the voltage; "
        "the smaller the value, the lower the voltage."),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // Is setting for lf?
    bool is_lf = arg_get_lit(ctx, 1);
    // the count of low levels of pwm output
    int count = arg_get_int_def(ctx, 2, 1000);

    CLIParserFree(ctx);

    // TODO DXL check response result is required

    if (count < 0 || count > 4095) {
        PrintAndLogEx(ERR, "Invalid count value: %d. It should be between 0 and 4095.", count);
        return PM3_EINVARG;
    }

    struct {
        uint8_t is_lf;
        uint16_t count;
    } PACKED params = {
        .is_lf = is_lf,
        .count = count,
    };

    // Start fpga config by mode
    PacketResponseNG resp;
    SendCommandNG(CMD_PM5_FPGA_SET_PWR_PWM_LOW_COUNT, (uint8_t *)&params, sizeof(params));
    PrintAndLogEx(INFO, "PWM value: " _YELLOW_("%d") ", for %s", count, is_lf ? "LF driver" : "HF driver");

    // Wait for response before sending data
    if (WaitForResponseTimeout(CMD_PM5_FPGA_SET_PWR_PWM_LOW_COUNT, &resp, 15000) == false) {
        PrintAndLogEx(WARNING, "set power pwm for fpga timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    PrintAndLogEx(SUCCESS, "Set PWM to FPGA for driver power control complete!");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",          CmdHelp,               AlwaysAvailable,  "This help"},
    {"-------------", CmdHelp,               AlwaysAvailable,  "----------------------- " _CYAN_("Operation") " -----------------------"},
    {"config",        CmdConfigFpga,         IfPm3Present,     "Configure FPGA for sram or flash"},
    {"pwrpwm",        CmdFpgaSetPowerPWM,    IfPm5,            "Adjust the input voltage of the driver through FPGA."},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdFPGA(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
