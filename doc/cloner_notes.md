# Notes on Cloner guns
<a id="Top"></a>

This document is based mostly on information posted on http://www.proxmark.org/forum/viewtopic.php?pid=39903#p39903


# Table of Contents

- [Notes on Cloner guns](#notes-on-cloner-guns)
- [Table of Contents](#table-of-contents)
- [Blue and black cloners](#blue-and-black-cloners)
- [White cloner (pre 2015)](#white-cloner-pre-2015)
- [White cloner (after 2016)](#white-cloner-after-2016)
- [White cloner (after 2016 D Quality)](#white-cloner-after-2016-d-quality)
- [Restore page1 data](#restore-page1-data)
- [Sniffing the comms](#sniffing-the-comms)


# Blue and black cloners
^[Top](#top)

3 variants: 
1. EM cloner
2. HID cloner
3. EM/HID cloner

Quality varies my manufacturer (Quality A (Good) until D (Bad))
They set a password on block 7 of the chip and set the password enable bit in block 0
```
Standard password is normally:    51243648
```
**Be sure to purchase the EM/HID version**

# White cloner (pre 2015)
^[Top](#top)

Multifrequency
Buttons light up BLUE
Reads data correctly
Coil performance acceptable 
```
Standard password is normally (for T55xx):  AA55BBBB
Standard password 13,56mHz:       individual per white cloner
```


# White cloner (after 2016)
^[Top](#top)

Multifrequency
Buttons light up  WHITE
Data scrambled (variable per individual cloner, possibly due to prevent legal issues)
Coil performance good
```
Standard password is normally (for T55xx):  AA55BBBB
Standard password 13,56mHz:       individual per white cloner
```


# White cloner (after 2016 D Quality)
^[Top](#top)

Multifrequency (it says so but it doesn't)
Only works for EM/HID card (125kHz)
High frequency not working
```
Standard password is normally (for T55xx):  AA55BBBB
```
**Note: Sets the HID card in TEST MODE**


# Restore page1 data
^[Top](#top)

```
lf t55xx write -b 1 -d E0150A48 --pg1
If t55xx write -b 2 -d 2D782308 --pg1
```

# Sniffing the comms
^[Top](#top)

The T55x7 protocol uses a pwm based protocol for writing to tags.  In order to make decoding easier try the new command as seen below instead. It will try to extract the data written.

```
-- after threshold limit 20 is triggered, skip 10000 samples before collecting samples.
lf config -s 10000 -t 20
lf t55xx sniff

-- if you have a save trace from before, try
data load -f xxxxxxx.pm3
lf t55xx sniff -1
```

It uses the existing `lf sniff` command to collect the data, so setting that first as per normal sniffing is recommended. Once you have a sniff, you can "re-sniff" from the stored sniffed data and try different settings, if you think the data is not clean.

As normal, the cloner may write data past the end of the 40K sample buffer. So using the `lf config -s <x bytes>` then re-run the sniff to see if there is more data.