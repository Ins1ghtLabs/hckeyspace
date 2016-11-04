# hckeyspace
Calculates Hashcat keyspace in Python as a C module

Usage:
run:
python setup.py build_ext --inplace

You'll get hckeyspace.so in the current directory. You'll also need the hashcat.hcstat in the same dir of .so file.


from hckeyspace import hckeyspace

print hckeyspace('?u?u?l?l?s?s')

736164

optional arguments:

hckeyspace(mask,hashmode,cust_char1,cust_char2,cust_char3,cust_char4)

int hashmode, default to 0, doesn't really matter unless the hash mode you are cracking has unicode.

str cust_char1...cust_char4, custom charsets, cust_char1 will be mapped to ?1 and so on, same as hashcat.


