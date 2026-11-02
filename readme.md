# Most Complete Amiibo Set Tracker Support Scripts
Provided in this sub folder are multiple python scripts for working with amiibo files, many of which leverage [Pyamiibo](https://github.com/tobywf/pyamiibo) and require `key-retail.bin` to do anything.

## Primary Tools
These are the main tools for working with amiibo bin files. Other similar ones exist, but I found them to be lacking in various ways. Namely, accuracy issues and oversights. My scripts have a lot of failsafes, and are far more careful than most other amiibo tools.

### py-amiitool.py
A reimplementation of the original [amiitool](https://github.com/socram8888/amiitool) with pyamiibo that is a billion times less annoying to use. Includes encrypt, decrypt, copy save, and reset, as well as a fix function to attempt to repair broken amiibo bin files (more effeciently mirroring all functionality of [TheAmiiboDoctor](https://github.com/amec0e/TheAmiiboDoctor). Also includes auto-functionality and drag-n-drop functionality. It only works with NTAG215s.

### amiibandtool.py
A tool for working with Super Nintendo World Powerup Bands, to my knowledge, the first of it's kind. These tags are NT3H2111. Has encrypt, decrypt functionality, as well as converting them to NTAG215 format. Kind of a more basic amiitool specifically for working with raw dumps of Power-Up Bands.

### amiibo-flippertool.py
A tool that works with dumps of amiibo in the flipper nfc plaintext file format. It can convert nfc to bin/raw, and it can convert bin/raw back to nfc for NTAG215 and NT3H2111. NT3H2211 (Amiibo v3) are currently unsupported.

### amiibo-generator.py
A tool that allows you to generate or mass generate amiibo NTAG215 bin files from a csv file containing IDs and names- or directly in the command line. This is very good at what it does, and generated files are functionally indistinguishable from real dumps. A companion script, `gen-amiibo-csv.py` is also included, which allows you to quickly generate a csv from a folder of amiibo for testing purposes.

### amiibo-uid-randomizer.py
A complete rewrite of [amiibo-sn-changer by DocKlokMan](https://gbatemp.net/threads/release-amiibo-bin-serial-changer.464702/) that uses pyamiibo instead of amiitool, it actually works properly and the UIDs it generates follow the standardization nintendo generally does, unlike the original tool. It also ditches jank user-input stuff for command line arguments.

### amiibo-trimpad.py
A simple tool that makes it easy to mass trim or expand amiibo bin files to different valid amiibo bin file sizes. There's some other functionality too there to assist with extensions and such for pixljs preprocessing. It's mainly for pixljs preprocessing, actually.

## Secondary Tools
These tools are the more useful tools for my repository. Info collection type stuff and utilities for making my life easier.

### amiibo-checker.py
A simple tool that checks and validates and outputs to the console the state of an amiibo bin file. Files with write counts of more than 0, and if the initialization bit is set get flagged, because MCAS is supposed to be all raw straight from the factory amiibo binary dumps. This needs more work though honestly. I want to check health of amiibo more comprehensively with it in a future version.

### pixljs-amiibo-sanity-checker.py
A simple tool that checks a folder to validate it against the path constraints and desirable file sizes of a pixljs based tag toy emulator, like the Flashiibo Pro.

