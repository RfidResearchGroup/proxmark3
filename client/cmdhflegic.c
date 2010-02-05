#include <stdio.h>
#include <string.h>
#include "proxusb.h"
#include "data.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhflegic.h"
#include "cmdmain.h"

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = 
{
  {"help",        CmdHelp,        1, "This help"},
  {"decode",      CmdLegicDecode, 0, "Display deobfuscated and decoded LEGIC RF tag data (use after hf legic reader)"},
  {"reader",      CmdLegicRFRead, 0, "[offset [length]] -- read bytes from a LEGIC card"},
  {NULL, NULL, 0, NULL}
};

int CmdHFLegic(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}

/*
 *  Output BigBuf and deobfuscate LEGIC RF tag data.
 *   This is based on information given in the talk held
 *  by Henryk Ploetz and Karsten Nohl at 26c3
 *  FIXME: will crash if sample buffer does not contain valid legic data
 */
int CmdLegicDecode(const char *Cmd)
{
  int h, i, j, k, n;
  int segment_len = 0;
  int segment_flag = 0;
  int stamp_len = 0;
  int crc = 0;
  int wrp = 0;
  int wrc = 0;
  int data_buf[1032]; // receiver buffer
  char out_string[3076]; // just use big buffer - bad practice
  char token_type[4];
  int delivered = 0;

  h = 0;
  
  // copy data from proxmark into buffer
  for (i = 0; i < 256; i += 12, h += 48) {
    UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
    SendCommand(&c);
    WaitForResponse(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
    
    for (j = 0; j < 48; j += 8) {
      for (k = 0; k < 8; k++) {
        data_buf[h+j+k] = sample_buf[j+k];
      }
      delivered += 8;
      if (delivered >= 1024)
        break;
    }
  }
    
  // Output CDF System area (9 bytes) plus remaining header area (12 bytes)
  
  PrintAndLog("\nCDF: System Area");
  
  PrintAndLog("MCD: %02x, MSN: %02x %02x %02x, MCC: %02x",
    data_buf[0],
    data_buf[1],
    data_buf[2],
    data_buf[3],
    data_buf[4]
  );
  
  crc = data_buf[4];
 
  switch (data_buf[5]&0x7f) {
    case 0x00 ... 0x2f:
      strncpy(token_type, "IAM",sizeof(token_type));
      break;
    case 0x30 ... 0x6f:
      strcpy(token_type, "SAM");
      break;
    case 0x70 ... 0x7f:
      strcpy(token_type, "GAM");
      break;
    default:
      strcpy(token_type, "???");
      break;
  }
  
  stamp_len = 0xfc - data_buf[6];
  
  PrintAndLog("DCF: %02x %02x, Token_Type=%s (OLE=%01u), Stamp_len=%02u",
    data_buf[5],
    data_buf[6],
    token_type,
    (data_buf[5]&0x80)>>7,
    stamp_len
  );
  
  PrintAndLog("WRP=%02u, WRC=%01u, RD=%01u, raw=%02x, SSC=%02x",
    data_buf[7]&0x0f,
    (data_buf[7]&0x70)>>4,
    (data_buf[7]&0x80)>>7,
    data_buf[7],
    data_buf[8]
  );
  
  PrintAndLog("Remaining Header Area");
  
  PrintAndLog("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
      data_buf[9],
    data_buf[10],
    data_buf[11],
    data_buf[12],
    data_buf[13],
    data_buf[14],
    data_buf[15],
    data_buf[16],
    data_buf[17],
    data_buf[18],
    data_buf[19],
    data_buf[20],
    data_buf[21]
  );
  
  PrintAndLog("\nADF: User Area");
  
  i = 22;  
  for (n=0; n<64; n++) {
    segment_len = ((data_buf[i+1]^crc)&0x0f) * 256 + (data_buf[i]^crc);
    segment_flag = ((data_buf[i+1]^crc)&0xf0)>>4;
    
    wrp = (data_buf[i+2]^crc);
    wrc = ((data_buf[i+3]^crc)&0x70)>>4;
    
     PrintAndLog("Segment %02u: raw header=%02x %02x %02x %02x, flag=%01x (valid=%01u, last=%01u), len=%04u, WRP=%02u, WRC=%02u, RD=%01u, CRC=%02x",
      n,
      data_buf[i]^crc,
      data_buf[i+1]^crc,
      data_buf[i+2]^crc,
      data_buf[i+3]^crc,
      segment_flag,
      (segment_flag&0x4)>>2,
      (segment_flag&0x8)>>3,
      segment_len,
      wrp,
      wrc,
      ((data_buf[i+3]^crc)&0x80)>>7,
      (data_buf[i+4]^crc)
    );
    
    i+=5;
    
    if (wrc>0) {
      PrintAndLog("WRC protected area:");
      for (k=0, j=0; k < wrc; k++, i++, j += 3) {
        sprintf(&out_string[j], "%02x", (data_buf[i]^crc));
        out_string[j+2] = ' ';
      };
        
      out_string[j] = '\0';
    
      PrintAndLog("%s", out_string);
    }
    
    if (wrp>wrc) {
      PrintAndLog("Remaining write protected area:");
      
      for (k=0, j=0; k < (wrp-wrc); k++, i++, j += 3) {
        sprintf(&out_string[j], "%02x", (data_buf[i]^crc));
        out_string[j+2] = ' ';
      };
    
      out_string[j] = '\0';
    
      PrintAndLog("%s", out_string);
      if((wrp-wrc) == 8) {
        sprintf(out_string,"Card ID: %2X%02X%02X",data_buf[i-4]^crc,data_buf[i-3]^crc,data_buf[i-2]^crc);
        PrintAndLog("%s", out_string);
      }
    }
    
    PrintAndLog("Remaining segment payload:");
    for (k=0, j=0; k < (segment_len - wrp - 5); k++, i++, j += 3) {
      sprintf(&out_string[j], "%02x", (data_buf[i]^crc));
      out_string[j+2] = ' ';
    };
    
    out_string[j] = '\0';
    
    PrintAndLog("%s", out_string);
    
    // end with last segment
    if (segment_flag & 0x8)
      return 0;
  };
  return 0;
}

int CmdLegicRFRead(const char *Cmd)
{
  int byte_count=0,offset=0;
  sscanf(Cmd, "%i %i", &offset, &byte_count);
  if(byte_count == 0) byte_count = 256;
  if(byte_count + offset > 256) byte_count = 256 - offset;
  UsbCommand c={CMD_READER_LEGIC_RF, {offset, byte_count, 0}};
  SendCommand(&c);
  return 0;
}
