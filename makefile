CXXFLAGS = -std=c++11 -O2

OBJ = portScan.o

portScan: $(OBJ)
	g++ -o portScan $(OBJ)

portScan.o:

.PHONY : clean
clean:
	rm -r *.o portScan
