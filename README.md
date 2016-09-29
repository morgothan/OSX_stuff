# OSX_stuff
JAMF Self Service Domain Credentials Harvester

#build requirements
Get and compile MacDBG
https://github.com/blankwall/MacDBG

Link Static
libtool -static debug_main.o util.o breakpoint.o exception.o memory.o thread.o dyldcache_parser.o .mach_gen/mach_excServer.o .mach_gen/mach_excUser.o -o libmcdb.a

#Compile Instructions
copy libmcdb.a to build dir
gcc -std=gnu99 libmcdb.a pullit.c -o pullit

#Usage
Ensure Self Service is running and the user has logged in at least once
sudo ./pullit



