include /usr/local/etc/PcapPlusPlus.mk #per digitalocean server
#include /home/ja/Documents/github/PcapPlusPlus/mk/PcapPlusPlus.mk #per wsl

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o craftberry main.o $(PCAPPP_LIBS)

# Clean Target
clear:
	rm main.o
	rm craftberry