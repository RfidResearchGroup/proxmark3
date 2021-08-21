# 
# Project automation script for fpga_hf 
# 
# Created for ISE version 10.1
# 
# This file contains several Tcl procedures (procs) that you can use to automate
# your project by running from xtclsh or the Project Navigator Tcl console.
# If you load this file (using the Tcl command: source fpga_hf.tcl, then you can
# run any of the procs included here.
# You may also edit any of these procs to customize them. See comments in each
# proc for more instructions.
# 
# This file contains the following procedures:
# 
# Top Level procs (meant to be called directly by the user):
#    run_process: you can use this top-level procedure to run any processes
#        that you choose to by adding and removing comments, or by
#        adding new entries.
#    rebuild_project: you can alternatively use this top-level procedure
#        to recreate your entire project, and the run selected processes.
# 
# Lower Level (helper) procs (called under in various cases by the top level procs):
#    show_help: print some basic information describing how this script works
#    add_source_files: adds the listed source files to your project.
#    set_project_props: sets the project properties that were in effect when this
#        script was generated.
#    create_libraries: creates and adds file to VHDL libraries that were defined when
#        this script was generated.
#    create_partitions: adds any partitions that were defined when this script was generated.
#    set_process_props: set the process properties as they were set for your project
#        when this script was generated.
# 

set myProject "fpga_hf.ise"
set myScript "fpga_hf.tcl"

# 
# Main (top-level) routines
# 

# 
# run_process
# This procedure is used to run processes on an existing project. You may comment or
# uncomment lines to control which processes are run. This routine is set up to run
# the Implement Design and Generate Programming File processes by default. This proc
# also sets process properties as specified in the "set_process_props" proc. Only
# those properties which have values different from their current settings in the project
# file will be modified in the project.
# 
proc run_process {} {

   global myScript
   global myProject

   ## put out a 'heartbeat' - so we know something's happening.
   puts "\n$myScript: running ($myProject)...\n"

   if { ! [ open_project ] } {
      return false
   }

   set_process_props
   #
   # Remove the comment characters (#'s) to enable the following commands 
   # process run "Synthesize"
   # process run "Translate"
   # process run "Map"
   # process run "Place & Route"
   #
   puts "Running 'Implement Design'"
   if { ! [ process run "Implement Design" ] } {
      puts "$myScript: Implementation run failed, check run output for details."
      project close
      return
   }
   puts "Running 'Generate Programming File'"
   if { ! [ process run "Generate Programming File" ] } {
      puts "$myScript: Generate Programming File run failed, check run output for details."
      project close
      return
   }

   puts "Run completed."
   project close

}

# 
# rebuild_project
# 
# This procedure renames the project file (if it exists) and recreates the project.
# It then sets project properties and adds project sources as specified by the
# set_project_props and add_source_files support procs. It recreates VHDL libraries
# and partitions as they existed at the time this script was generated.
# 
# It then calls run_process to set process properties and run selected processes.
# 
proc rebuild_project {} {

   global myScript
   global myProject

   ## put out a 'heartbeat' - so we know something's happening.
   puts "\n$myScript: rebuilding ($myProject)...\n"

   if { [ file exists $myProject ] } { 
      puts "$myScript: Removing existing project file."
      file delete $myProject
   }

   puts "$myScript: Rebuilding project $myProject"
   project new $myProject
   set_project_props
   add_source_files
   create_libraries
   create_partitions
   puts "$myScript: project rebuild completed."

   run_process

}

# 
# Support Routines
# 

# 
# show_help: print information to help users understand the options available when
#            running this script.
# 
proc show_help {} {

   global myScript

   puts ""
   puts "usage: xtclsh $myScript <options>"
   puts "       or you can run xtclsh and then enter 'source $myScript'."
   puts ""
   puts "options:"
   puts "   run_process       - set properties and run processes."
   puts "   rebuild_project   - rebuild the project from scratch and run processes."
   puts "   set_project_props - set project properties (device, speed, etc.)"
   puts "   add_source_files  - add source files"
   puts "   create_libraries  - create vhdl libraries"
   puts "   create_partitions - create partitions"
   puts "   set_process_props - set process property values"
   puts "   show_help         - print this message"
   puts ""
}

proc open_project {} {

   global myScript
   global myProject

   if { ! [ file exists $myProject ] } { 
      ## project file isn't there, rebuild it.
      puts "Project $myProject not found. Use ${myProject}_rebuild to recreate it."
      return false
   }

   project open $myProject

   return true

}
# 
# set_project_props
# 
# This procedure sets the project properties as they were set in the project
# at the time this script was generated.
# 
proc set_project_props {} {

   global myScript

   if { ! [ open_project ] } {
      return false
   }

   puts "$myScript: Setting project properties..."

   project set family "Spartan3E"
   project set device "xc3s100e"
   project set package "vq100"
   project set speed "-4"
   project set top_level_module_type "HDL"
   project set synthesis_tool "XST (VHDL/Verilog)"
   project set simulator "ISE Simulator (VHDL/Verilog)"
   project set "Preferred Language" "Verilog"
   project set "Enable Message Filtering" "false"
   project set "Display Incremental Messages" "false"

}


# 
# add_source_files
# 
# This procedure add the source files that were known to the project at the
# time this script was generated.
# 
proc add_source_files {} {

   global myScript

   if { ! [ open_project ] } {
      return false
   }

   puts "$myScript: Adding sources to project..."

   xfile add "../../clk_divider.v"
   xfile add "../../define.v"
   xfile add "../../fpga.ucf"
   xfile add "../../fpga_allinone.v"
   xfile add "../../fpga_hfmod.v"
   xfile add "../../fpga_lfmod.v"
   xfile add "../../hi_flite.v"
   xfile add "../../hi_get_trace.v"
   xfile add "../../hi_iso14443a.v"
   xfile add "../../hi_reader.v"
   xfile add "../../hi_simulate.v"
   xfile add "../../hi_sniffer.v"
   xfile add "../../lf_edge_detect.v"
   xfile add "../../lo_adc.v"
   xfile add "../../lo_edge_detect.v"
   xfile add "../../lo_passthru.v"
   xfile add "../../lo_read.v"
   xfile add "../../lp20khz_1MSa_iir_filter.v"
   xfile add "../../mux2_onein.v"
   xfile add "../../mux2_oneout.v"
   xfile add "../../util.v"

   # Set the Top Module as well...
   project set top "fpga_hf"

   puts "$myScript: project sources reloaded."

} ; # end add_source_files

# 
# create_libraries
# 
# This procedure defines VHDL libraries and associates files with those libraries.
# It is expected to be used when recreating the project. Any libraries defined
# when this script was generated are recreated by this procedure.
# 
proc create_libraries {} {

   global myScript

   if { ! [ open_project ] } {
      return false
   }

   puts "$myScript: Creating libraries..."


   # must close the project or library definitions aren't saved.
   project close

} ; # end create_libraries

#
# create_partitions
#
# This procedure creates partitions on instances in your project.
# It is expected to be used when recreating the project. Any partitions
# defined when this script was generated are recreated by this procedure.
# 
proc create_partitions {} {

   global myScript

   if { ! [ open_project ] } {
      return false
   }

   puts "$myScript: Creating Partitions..."


   # must close the project or partition definitions aren't saved.
   project close

} ; # end create_partitions

# 
# set_process_props
# 
# This procedure sets properties as requested during script generation (either
# all of the properties, or only those modified from their defaults).
# 
proc set_process_props {} {

   global myScript

   if { ! [ open_project ] } {
      return false
   }

   puts "$myScript: setting process properties..."

   project set "Compiled Library Directory" "\$XILINX/<language>/<simulator>"
   project set "Use SmartGuide" "false"
   project set "SmartGuide Filename" "fpga_hf_guide.ncd"
   project set "Multiplier Style" "Auto" -process "Synthesize - XST"
   project set "Configuration Rate" "Default (1)" -process "Generate Programming File"
   project set "Map to Input Functions" "4" -process "Map"
   project set "Number of Clock Buffers" "24" -process "Synthesize - XST"
   project set "Max Fanout" "500" -process "Synthesize - XST"
   project set "Case Implementation Style" "None" -process "Synthesize - XST"
   project set "Decoder Extraction" "true" -process "Synthesize - XST"
   project set "Priority Encoder Extraction" "Yes" -process "Synthesize - XST"
   project set "Mux Extraction" "Yes" -process "Synthesize - XST"
   project set "RAM Extraction" "true" -process "Synthesize - XST"
   project set "ROM Extraction" "true" -process "Synthesize - XST"
   project set "FSM Encoding Algorithm" "Auto" -process "Synthesize - XST"
   project set "Logical Shifter Extraction" "true" -process "Synthesize - XST"
   project set "Optimization Goal" "Speed" -process "Synthesize - XST"
   project set "Optimization Effort" "Normal" -process "Synthesize - XST"
   project set "Resource Sharing" "true" -process "Synthesize - XST"
   project set "Shift Register Extraction" "true" -process "Synthesize - XST"
   project set "XOR Collapsing" "true" -process "Synthesize - XST"
   project set "Other Bitgen Command Line Options" "" -process "Generate Programming File"
   project set "Show All Models" "false" -process "Generate IBIS Model"
   project set "Target UCF File Name" "" -process "Back-annotate Pin Locations"
   project set "Ignore User Timing Constraints" "false" -process "Map"
   project set "Use RLOC Constraints" "true" -process "Map"
   project set "Other Map Command Line Options" "" -process "Map"
   project set "Use LOC Constraints" "true" -process "Translate"
   project set "Other Ngdbuild Command Line Options" "" -process "Translate"
   project set "Ignore User Timing Constraints" "false" -process "Place & Route"
   project set "Other Place & Route Command Line Options" "" -process "Place & Route"
   project set "UserID Code (8 Digit Hexadecimal)" "0xFFFFFFFF" -process "Generate Programming File"
   project set "Reset DCM if SHUTDOWN & AGHIGH performed" "false" -process "Generate Programming File"
   project set "Configuration Pin Done" "Pull Up" -process "Generate Programming File"
   project set "Create ASCII Configuration File" "false" -process "Generate Programming File"
   project set "Create Binary Configuration File" "false" -process "Generate Programming File"
   project set "Create Bit File" "true" -process "Generate Programming File"
   project set "Enable BitStream Compression" "false" -process "Generate Programming File"
   project set "Run Design Rules Checker (DRC)" "true" -process "Generate Programming File"
   project set "Enable Cyclic Redundancy Checking (CRC)" "true" -process "Generate Programming File"
   project set "Create IEEE 1532 Configuration File" "false" -process "Generate Programming File"
   project set "Configuration Pin Program" "Pull Up" -process "Generate Programming File"
   project set "JTAG Pin TCK" "Pull Up" -process "Generate Programming File"
   project set "JTAG Pin TDI" "Pull Up" -process "Generate Programming File"
   project set "JTAG Pin TDO" "Pull Up" -process "Generate Programming File"
   project set "JTAG Pin TMS" "Pull Up" -process "Generate Programming File"
   project set "Unused IOB Pins" "Pull Down" -process "Generate Programming File"
   project set "Security" "Enable Readback and Reconfiguration" -process "Generate Programming File"
   project set "FPGA Start-Up Clock" "CCLK" -process "Generate Programming File"
   project set "Done (Output Events)" "Default (4)" -process "Generate Programming File"
   project set "Drive Done Pin High" "false" -process "Generate Programming File"
   project set "Enable Outputs (Output Events)" "Default (5)" -process "Generate Programming File"
   project set "Release DLL (Output Events)" "Default (NoWait)" -process "Generate Programming File"
   project set "Release Write Enable (Output Events)" "Default (6)" -process "Generate Programming File"
   project set "Enable Internal Done Pipe" "false" -process "Generate Programming File"
   project set "Allow Logic Optimization Across Hierarchy" "false" -process "Map"
   project set "Optimization Strategy (Cover Mode)" "Area" -process "Map"
   project set "Disable Register Ordering" "false" -process "Map"
   project set "Pack I/O Registers/Latches into IOBs" "Off" -process "Map"
   project set "Replicate Logic to Allow Logic Level Reduction" "true" -process "Map"
   project set "Generate Detailed MAP Report" "false" -process "Map"
   project set "Map Slice Logic into Unused Block RAMs" "false" -process "Map"
   project set "Perform Timing-Driven Packing and Placement" "false" -process "Map"
   project set "Trim Unconnected Signals" "true" -process "Map"
   project set "Create I/O Pads from Ports" "false" -process "Translate"
   project set "Macro Search Path" "" -process "Translate"
   project set "Netlist Translation Type" "Timestamp" -process "Translate"
   project set "User Rules File for Netlister Launcher" "" -process "Translate"
   project set "Allow Unexpanded Blocks" "false" -process "Translate"
   project set "Allow Unmatched LOC Constraints" "false" -process "Translate"
   project set "Starting Placer Cost Table (1-100)" "1" -process "Place & Route"
   project set "Placer Effort Level (Overrides Overall Level)" "None" -process "Place & Route"
   project set "Router Effort Level (Overrides Overall Level)" "None" -process "Place & Route"
   project set "Place And Route Mode" "Normal Place and Route" -process "Place & Route"
   project set "Use Bonded I/Os" "false" -process "Place & Route"
   project set "Add I/O Buffers" "true" -process "Synthesize - XST"
   project set "Global Optimization Goal" "AllClockNets" -process "Synthesize - XST"
   project set "Keep Hierarchy" "No" -process "Synthesize - XST"
   project set "Register Balancing" "No" -process "Synthesize - XST"
   project set "Register Duplication" "true" -process "Synthesize - XST"
   project set "Asynchronous To Synchronous" "false" -process "Synthesize - XST"
   project set "Automatic BRAM Packing" "false" -process "Synthesize - XST"
   project set "BRAM Utilization Ratio" "100" -process "Synthesize - XST"
   project set "Bus Delimiter" "<>" -process "Synthesize - XST"
   project set "Case" "Maintain" -process "Synthesize - XST"
   project set "Cores Search Directories" "" -process "Synthesize - XST"
   project set "Cross Clock Analysis" "false" -process "Synthesize - XST"
   project set "Equivalent Register Removal" "true" -process "Synthesize - XST"
   project set "FSM Style" "LUT" -process "Synthesize - XST"
   project set "Generate RTL Schematic" "Yes" -process "Synthesize - XST"
   project set "Generics, Parameters" "" -process "Synthesize - XST"
   project set "Hierarchy Separator" "/" -process "Synthesize - XST"
   project set "HDL INI File" "" -process "Synthesize - XST"
   project set "Library Search Order" "" -process "Synthesize - XST"
   project set "Netlist Hierarchy" "As Optimized" -process "Synthesize - XST"
   project set "Optimize Instantiated Primitives" "false" -process "Synthesize - XST"
   project set "Pack I/O Registers into IOBs" "Auto" -process "Synthesize - XST"
   project set "Read Cores" "true" -process "Synthesize - XST"
   project set "Slice Packing" "true" -process "Synthesize - XST"
   project set "Slice Utilization Ratio" "100" -process "Synthesize - XST"
   project set "Use Clock Enable" "Yes" -process "Synthesize - XST"
   project set "Use Synchronous Reset" "Yes" -process "Synthesize - XST"
   project set "Use Synchronous Set" "Yes" -process "Synthesize - XST"
   project set "Use Synthesis Constraints File" "true" -process "Synthesize - XST"
   project set "Custom Compile File List" "" -process "Synthesize - XST"
   project set "Verilog Include Directories" "" -process "Synthesize - XST"
   project set "Verilog 2001" "true" -process "Synthesize - XST"
   project set "Verilog Macros" "" -process "Synthesize - XST"
   project set "Work Directory" "./xst" -process "Synthesize - XST"
   project set "Write Timing Constraints" "false" -process "Synthesize - XST"
   project set "Other XST Command Line Options" "" -process "Synthesize - XST"
   project set "Map Effort Level" "Medium" -process "Map"
   project set "Combinatorial Logic Optimization" "false" -process "Map"
   project set "Starting Placer Cost Table (1-100)" "1" -process "Map"
   project set "Power Reduction" "false" -process "Map"
   project set "Register Duplication" "false" -process "Map"
   project set "Synthesis Constraints File" "" -process "Synthesize - XST"
   project set "Mux Style" "Auto" -process "Synthesize - XST"
   project set "RAM Style" "Auto" -process "Synthesize - XST"
   project set "Timing Mode" "Non Timing Driven" -process "Map"
   project set "Generate Asynchronous Delay Report" "false" -process "Place & Route"
   project set "Generate Clock Region Report" "false" -process "Place & Route"
   project set "Generate Post-Place & Route Simulation Model" "false" -process "Place & Route"
   project set "Generate Post-Place & Route Static Timing Report" "true" -process "Place & Route"
   project set "Nodelist File (Unix Only)" "" -process "Place & Route"
   project set "Number of PAR Iterations (0-100)" "3" -process "Place & Route"
   project set "Save Results in Directory (.dir will be appended)" "" -process "Place & Route"
   project set "Number of Results to Save (0-100)" "" -process "Place & Route"
   project set "Power Reduction" "false" -process "Place & Route"
   project set "Timing Mode" "Performance Evaluation" -process "Place & Route"
   project set "Enable Debugging of Serial Mode BitStream" "false" -process "Generate Programming File"
   project set "CLB Pack Factor Percentage" "100" -process "Map"
   project set "Place & Route Effort Level (Overall)" "Standard" -process "Place & Route"
   project set "Move First Flip-Flop Stage" "true" -process "Synthesize - XST"
   project set "Move Last Flip-Flop Stage" "true" -process "Synthesize - XST"
   project set "ROM Style" "Auto" -process "Synthesize - XST"
   project set "Safe Implementation" "No" -process "Synthesize - XST"
   project set "Extra Effort" "None" -process "Map"
   project set "Power Activity File" "" -process "Map"
   project set "Power Activity File" "" -process "Place & Route"
   project set "Extra Effort (Highest PAR level only)" "None" -process "Place & Route"

   puts "$myScript: project property values set."

} ; # end set_process_props

proc main {} {

   if { [llength $::argv] == 0 } {
      show_help
      return true
   }

   foreach option $::argv {
      switch $option {
         "show_help"           { show_help }
         "run_process"         { run_process }
         "rebuild_project"     { rebuild_project }
         "set_project_props"   { set_project_props }
         "add_source_files"    { add_source_files }
         "create_libraries"    { create_libraries }
         "create_partitions"   { create_partitions }
         "set_process_props"   { set_process_props }
         default               { puts "unrecognized option: $option"; show_help }
      }
   }
}

if { $tcl_interactive } {
   show_help
} else {
   if {[catch {main} result]} {
      puts "$myScript failed: $result."
   }
}

