#####################################################*
#####################################################*
#*                Makefile  MD5PASS.C                *
#*                     v0.2.0                        *
#*            Data: 10/03/20013                      *
#*                                                   *
#*                                                   *
#*       .....................................       *
#*                                                   *
#*      Felipe Ecker (Khun) - khun@hexcodes.org      *
#*                                                   *
#*                                                   *
#####################################################*

CC = gcc
FLAG = -O2 -Wall -Werror
BIN	= ./bin/

md5pass: md5pass.c
	$(CC) $(FLAG) -o md5pass md5pass.c

clean:
	rm -rf md5pass

