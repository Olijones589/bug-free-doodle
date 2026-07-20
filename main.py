import cmpr
from os import system

res = cmpr.gen_compile("awesomes.lua")

file = open("tmp.nasm", "w")
file.write(res)
file.close()

system("nasm -felf64 tmp.nasm -o tmp.o && ld tmp.o")
