#!/bin/bash

## 20160116, iceman
## remove old
rm /home/user/cov-analysis-linux-7.7.0.4/config/coverity_config.xml
rm -rf /home/user/cov-analysis-linux-7.7.0.4/config/gcc-config-?
rm -rf /home/user/cov-analysis-linux-7.7.0.4/config/g++-config-?


## Configure ARM ,  make sure you have the arm gcc in your $PATH variable.
cov-configure -co arm-none-eabi-gcc -- -mthumb-interwork



