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

test2:
	rm test.o
	rm test
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o test.o test.cpp  -lnetfilter_queue
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o test test.o $(PCAPPP_LIBS)  -lnetfilter_queue

nfqueue:
	# rm nfqueue_test.o
	# rm nfqueue_test
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o nfqueue_test.o nfqueue_test.cpp -lnetfilter_queue
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o nfqueue_test nfqueue_test.o $(PCAPPP_LIBS) -lnetfilter_queue