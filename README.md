# HVFUZZ
  - Summary
    - Hyper-V Fuzzer using hAFL2
    - This fuzzer was manufactured based on hAFL2, and HyperViper's technology is partially included. 
    - Since the targets of these two fuzzers were different from my target, I developed a new fuzzer.
  - Reference
    - [hAFL2](https://github.com/SafeBreach-Labs/hAFL2)
    - [HyperViper](https://github.com/JaanusKaapPublic/HyperViper)


# Modules
  - CPHarness
     - Running on kernel of level2 
     - It only targets `storvsp/storvsc`. 
     - Send payload from guest to host
  - packet_sender (In progress)
     - Running on user land of level2 
     - Send payload from user to kernel(CPHarness)

# Appendix
   - [This](https://github.com/blackcon/HVFUZZ/issues/1) is that I recorded my shoveling journey for fuzzer setting.
