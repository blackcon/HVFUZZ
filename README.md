# HVFUZZ
Hyper-V Fuzzer using hAFL2

## Modules
  - CPHarness
     - Running on kernel of level2 
     - It only targets `storvsp/storvsc`. 
     - Send payload from guest to host
  - packet_sender (In progress)
     - Running on user land of level2 
     - Send payload from user to kernel(CPHarness)
