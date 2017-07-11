#!/bin/bash

## 20160116, iceman
## remove old
rm /home/user/cov-analysis-linux-2017.07/config/coverity_config.xml
rm -rf /home/user/cov-analysis-linux-2017.07/config/gcc-config-?
rm -rf /home/user/cov-analysis-linux-2017.07/config/g++-config-?
 
 ## Configure ARM ,  make sure you have the arm gcc in your $PATH variable.
#/home/user/cov-analysis-linux-2017.07/bin/cov-configure -co arm-none-eabi-gcc -- -mthumb-interwork
/home/user/cov-analysis-linux-2017.07/bin/cov-configure -co arm-none-eabi-gcc -- -std=c99 -mthumb -mthumb-interwork

echo "Done."