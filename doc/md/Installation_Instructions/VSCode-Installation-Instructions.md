# Visual Studio Code for debugging

Download and install [Visual Studio Code](https://code.visualstudio.com/) 

Download and install [J-Link Software and Documentation pack](https://www.segger.com/downloads/jlink) 


## Debian / Ubuntu / Kali / ParrotOS / Raspbian

Install dependencies

```sh
sudo apt-get install --no-install-recommends binutils-arm-none-eabi gdb openocd gdb-multiarch
```

On some systems `arm-none-eabi-gdb` was replaced with `gdb-multiarch`. In order to use the J-Link debugger you need to link `arm-none-eabi-gdb` to `gdb-multiarch`:
```sh
ln -s /usr/bin/gdb-multiarch /usr/bin/arm-none-eabi-gdb
```

Setup the Visual Studio Code configuration, by going into your project folder and run:
```sh
./.vscode/setup.sh
```

now launch Visual Studio Code and open your project folder


## Windows: WSL

Enter WSL prompt (`wsl` or `start windows terminal`)

Install dependencies
```sh
sudo apt-get install --no-install-recommends binutils-arm-none-eabi gdb openocd gdb-multiarch
```

The J-Link debugger requires `arm-none-eabi-gdb` which was replaced with `gdb-multiarch`. In order to use the J-Link debugger link `arm-none-eabi-gdb` to `gdb-multiarch`:
```sh
sudo ln -s /usr/bin/gdb-multiarch /usr/bin/arm-none-eabi-gdb
```

Setup the Visual Studio Code configuration, by going into your project folder and run:
```sh
./.vscode/setup.sh
```

and launch Visual Studio Code
```sh
code .
```


## Windows: ProxSpace

Download and install [Visual Studio Code](https://code.visualstudio.com/) 

Download and install [J-Link Software and Documentation pack for Windows](https://www.segger.com/downloads/jlink/JLink_Windows.exe) 

Enter PorxSpace (`runme64.bat`)  and enter your project folder.

Setup the Visual Studio Code configuration, by running:
```sh
./.vscode/setup.sh
```

now launch Visual Studio Code and open your project folder



_note_
Please install the recommended Visual Studio Code extensions in order for debugging to work.