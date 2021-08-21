#!/bin/bash

(
  cd iseproj/fpga_hf
  xtclsh fpga_hf.tcl run_process
  mv fpga_hf.bit ../..
  git checkout fpga_hf.ise
  git clean -dfx .
)
