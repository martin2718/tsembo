# tsembo

## Environment

- OS: Fedora Linux release 42 (Adams)
- Compiler: gcc version 15.2.1 20260123 (Red Hat 15.2.1-7) (GCC)
- Build system: CMake

## How to compile

- install dependencies
  - libpcap-devel
  - libgtest-devel
- configure cmake project
  - go to the project folder
  - run `cmake -S . -B build`
- build the application
  - run `make -C build`

## How to run

- It loads .pcap file and write the output into .csv file with the same name
  - `build/src/tsembo file.pcap`
  - The output files is written as `file.csv`

```bash
$ build/src/tsembo 20241105_051.test.pcap 
Wrote 171 issues to 20241105_051.test.csv
```

## The application was built with help of Github copilot and cursor AI.
