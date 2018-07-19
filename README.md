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

To install the required libusb version on Ubuntu or Debian run `sudo apt-get install libusb-1.0`

Building
-------
```
~/omap_usbload $ make
gcc -Wall -O2 -I/usr/include/libusb-1.0 -c omap_loader.c -o omap_loader.o
gcc  -o omap_loader omap_loader.o -lusb-1.0
~/omap_usbload $ ./omap_loader --help
```
    
Running
-------
```
OMAP Loader 1.0.0
Usage: ./omap_loader [options] -f first-stage [-f file -a addr]...
Options:
  -f, --file      Provide the filename of a binary file to be
                  uploaded. The first file specified is uploaded to
                  the fixed address 0x40200000 as defined by the manual.
                  Additional files must be followed by an address
                  argument (-a).
  -a, --addr      The address to load the prior file at.
  -j, --jump      Specify the address to jump to after loading all
                  of the files in to memory.
  -i, --vendor    Override the default vendor ID to poll for
                  (default 0x0451).
  -p, --product   Override the default product ID to poll for
                  (default 0xd00e).
  -h, --help      Display this message.
  -v, --verbose   Enable verbose output.
```

Examples
--------
Uploading a compatible X-Loader, U-Boot, Kernel, and RAMDisk, then jumping
to the U-Boot image for further bootloading:
`./omap_loader -f x-load.bin -f u-boot.bin -a 0x80200000 -f uImage -a 0x80800000 \
   -f uRamdisk -a 0x81000000 -j 0x80200000`
   
Uploading arbitrary code to be executed (doesn't have to be X-loader):
`./omap_loader -f exec_me.bin`

Trying to debug an upload issue using verbose output:
`./omap_loader -v -f exec_me.bin -f file1.bin -a 0xdeadbeef -j 0xabad1dea`

Support
-------
If you experience any difficulties in building or using this project, please search through the open issues or open a new one describing your problem. Currently, the maintainer \[me\] does not own a USBLOAD compatible device. This means any device testing is impossible on my end.

License
-------
GNU GPLv2

Authors
-------
Grant Hernandez (2014) <br/>
Martin Mueller (2008) - original omap3\_usbload
