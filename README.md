OMAP Loader
===========
OMAP Loader is a libUSB 1.0 rewrite of the omap3\_usbload utility.
Essentially it is a USB BootROM uploading utility for TI ARM OMAP3 family processors. 
The motivation to rewrite this came from using the utility to upload code
on to Nest Thermostats.

This rewrite is versioned and implements all of the original features.
Supports USBLOAD functionality in TI's X-Loader (Google: omap3\_usbload for more info)

Build Requirements
-------
* GCC or a compatible C compiler is required
* GNU Make
* libUSB 1.0.X or higher

Building
-------
    ~/omap_usbload $ make
    gcc -Wall -O2 -I/usr/include/libusb-1.0 -c omap_loader.c -o omap_loader.o
    gcc  -o omap_loader omap_loader.o -lusb-1.0
    ~/omap_usbload $ ./omap_loader --help

License
-------
GNU GPLv2

Authors
-------
Grant Hernandez (2014) <br/>
Martin Mueller (2008) - original omap3\_usbload
