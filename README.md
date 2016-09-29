# OSX_stuff
JAMF Self Service Domain Credentials Harvester

#build requirements
1. Get and compile MacDBG

https://github.com/blankwall/MacDBG

2. Link Static

libtool -static debug_main.o util.o breakpoint.o exception.o memory.o thread.o dyldcache_parser.o .mach_gen/mach_excServer.o .mach_gen/mach_excUser.o -o libmcdb.a

#Compile Instructions
1. copy pullit.c into the macdbg src build dir
2. gcc -std=gnu99 libmcdb.a pullit.c -o pullit

#Usage
1. Ensure Self Service is running and the user has logged in at least once
2. sudo ./pullit



