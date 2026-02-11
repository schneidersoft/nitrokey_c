SRCS= \
    curve25519/source/curve25519_mehdi.c \
    curve25519/source/curve25519_order.c \
    curve25519/source/curve25519_utils.c \
    curve25519/source/curve25519_dh.c \
    curve25519/source/ed25519_sign.c \
    curve25519/source/ed25519_verify.c \
    curve25519/source/sha512.c \
    curve25519/source/custom_blind.c


all: curve25519
	gcc -Wall -Werror -o main main.c $(SRCS) $(shell pkg-config --cflags --libs libpcsclite)

curve25519:
	git clone --depth=1 https://github.com/msotoodeh/curve25519.git
	