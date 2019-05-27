1.	FEATURES

•	Built-in Bluetooth 2.0 with EDR Bluetooth module, default baud rate 115200.
•	Built-in 400 mAh polymer lithium-ion battery, typical standby time up to 3.5 hours.
•	Additional heat dissipating fins can significantly reduce the temperature when the HF antenna is in operation for a long time.
•	Complete lithium charging management system, seamless switching power supply. Full overcharge and overdischarge protection.
•	Bluetooth has an independent power switch that can be turned on or off.
•	It's compact and easy to carry. The clamp structure is easy to install and replace.


It can easily connect to Bluetooth mobile phone, portable computer, etc. Without USB cable, complicated permissions or driver settings.

Built-in battery can support standalone mode, off-line sniffing, off-line reading & simulation, etc. The temperature of the device is stable.



2.	PARAMETER

•	Battery capacity:	400 mAh
•	Standby time:	3.5h@StandBy; 2.9h@LF-On; 50min@HF-On;
•	Charging Current:	200mA (Plug in USB Default Charging)
•	Charging time:	2.5h
•	Bluetooth power:	4dBm, -85 dBm@2Mbps
•	Bluetooth distance:	6m (depending on the environment and device orientation)
•	Size and weight:	54.4mm*29.4mm*13.5mm 24g


3.	ASSEMBLY STEPS

①	Remove the plastic upper case of PM3 RDV40 by opener.
②	The antenna is temporarily removed with a screwdriver to expose the FPC interface.
③	Turn off all power switches, insert the FPC wire into the FPC connector, and lock the FPC connector.
④	Tear off the blue film of heat conductive double-sided tape. Align the add-on to the hole positions and gently insert it into the case.
⑤	Assembly finished!


  


4.	CONNECT WITH BLUETOOTH

(1)	Connecting rdv4.0 with Bluetooth on mobile phone or computer
①	Open Bluetooth and search for a device named PM3_RDV4.0.
②	Enter the paired password 1234 and establish the connection.
③	The blue state LED on the ADD-ON will keep blinking after the connection is established. Only when the mobile phone or computer opens the correct COM port, the blue LED turns on solid, indicating that the connection is successful.

(2)	Fast connection using dedicated USB Bluetooth adapter
①	Install driver:
http://www.silabs.com/products/development-tools/software/usb-to-uart-bridge-vcp-drivers  
②	Insert the adapter into the USB port. The adapter will search automatically and establish the connection. The adapter will remember the device that was first connected and after that the same device will be connected.
③	The adapter button can be used to delete memory so that other add-on can be searched and connected.
④	After the connection is established, the blue state LED on ADD-ON will turn on solid.
                               


Compiling / Flashing 
Please download the latest source code from RRG's Github repo:
https://github.com/RfidResearchGroup/proxmark3



5.	OTHER NOTES

(1)	UART and LED behavior

Bluetooth is connected to PM3 RDV4.0 via UART. The USB and UART interfaces of RDV4.0 can coexist without conflict, and no special switching is required. 

The following link has helpful notes on UART usage and baud rates:
https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/uart_notes.md

(2)	Disassembly

There is a heat conductive double-sided tape inside the Add-on, which has strong adhesive force. Therefore, if add-on needs to be removed, it needs to be pulled out from the heat sink end with greater efforts. Each disassembly will reduce the viscidity of double-sided tape. When double-sided tape is well protected, it will not affect the second use. Thermal conductivity will be slightly worse and will therefore have a direct impact on the thermal performance of the heat sink.

(3)	Battery charging

The battery charging circuit is turned on by default. Any time a USB cable is inserted, the battery will be automatically charged. The red LED will remain bright when charging. 
The red LED will be extinguished when charging is completed.

(4)	Get better signals

For the better heat dissipation, we have used a cast metal enclosure for the add-on. As a result Bluetooth wireless signals are sacrificed. For example, if the back of ADDON is facing the Bluetooth host, the signal is very bad and the distance will be reduced. The best signal strength can be obtained when the front glass faces the Bluetooth host.
	If the PM3 is not responding, it may be due to a poor Bluetooth connection. To improve performance, try repositioning the PM3 so the glass face is directed toward the host.

