# Notes on Cloner gunes

This document is based mostly on information posted on http://www.proxmark.org/forum/viewtopic.php?pid=39903#p39903

- [Blue and black cloners](#blue-and-black-cloners)
- [White cloner (pre 2015)](#white-cloner-pre-2015)
- [White cloner (after 2016)](#white-cloner-after-2016)
- [White cloner (after 2016 D Quality)](#white-cloner-after-2016-d-quality)
- [restore page1 data](#restore-page1-data)


# Blue and black cloners

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

Multifrequency
Buttons light up BLUE
Reads data correctly
Coil performance acceptable 
```
Standard password is normally (for T55xx):  AA55BBBB
Standard password 13,56mHz:       individual per white cloner
```


# White cloner (after 2016)
Multifrequency
Buttons light up  WHITE
Data scrambled (variable per individual cloner, possibly due to prevent legal issues)
Coil performance good
```
Standard password is normally (for T55xx):  AA55BBBB
Standard password 13,56mHz:       individual per white cloner
```


# White cloner (after 2016 D Quality)
Multifrequency (it says so but it doesn't)
Only works for EM/HID card (125kHz)
High frequency not working
```
Standard password is normally (for T55xx):  AA55BBBB
```
**Note: Sets the HID card in TEST MODE**


# Restore page1 data
```
lf t55xx write b 1 d E0150A48 1
If t55xx write b 2 d 2D782308 1
```
