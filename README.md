# NpktLib
"Virtual Packet Driver" for windows x86/x64 based on NpCap (or WinPCap)

I've been using "Packet drivers" for many years, under MsDos and Windows 16,
under Win 32 across a Virtual packet driver... for teaching purposes.
But I had a recent pb under Win 64 because kernel network driver type has changed to NDIS6,
and existing software only ran on 32-bit platforms with NDIS5.

That's why I have developped this little library, which works over NpCap or WinPCap 
on x86 32-bit or x64 Windows platforms.

Just create à Visual C++ Win32-Console project, add all the files, write a C program
after looking at NtPktDrv.rtf (help file) and you'll be able to read / write
raw Ethernet frame on the network very simply !

I have tested it succesfully with ARP and ICMP.
For higher level protocols it's better to use sockets.
