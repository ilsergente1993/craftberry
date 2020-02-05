include /usr/local/etc/PcapPlusPlus.mk #per digitalocean server
#include /home/ja/Documents/github/PcapPlusPlus/mk/PcapPlusPlus.mk #per wsl

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main.cpp -lnetfilter_queue
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o craftberry main.o $(PCAPPP_LIBS) -lnetfilter_queue

# Clean Target
clear:
	rm main.o
	rm craftberry

first:
	#rm nfqueue_test2.o
	#rm nfqueue_test2
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main2.o main2.cpp -lnetfilter_queue
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o main2 main2.o $(PCAPPP_LIBS) -lnetfilter_queue

second:
	#rm nfqueue_test2.o
	#rm nfqueue_test2
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o nfqueue_test.o nfqueue_test.cpp -lnetfilter_queue
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o nfqueue_test nfqueue_test.o $(PCAPPP_LIBS) -lnetfilter_queue