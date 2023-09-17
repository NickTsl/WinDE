# WinDE

## is_driver_vulnerable.py
This is the half-finished taint analysis tool to automatically scan for vulnerable drivers, by assigning a symbolic expression to user inputs, and seeing where they are used. If physical memory mapping functions accept user-supplied inputs, then there's a vulnerability.

## WinDE.cpp 
This is just a PoC to send specially crafted commands to the vulnerable drivers, to try and escalate privileges.
