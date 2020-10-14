CC = gcc
CFALGS = -std=c99 -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-all -z noexecstack -pie -fPIE -z now -s

main: main.c
	$(CC) $(CFALGS) $^ -o pwn