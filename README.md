# HVFUZZ
  - Summary
    - Hyper-V Fuzzer using hAFL2
    - This fuzzer was manufactured based on [hAFL2](https://github.com/SafeBreach-Labs/hAFL2), and [HyperViper](https://github.com/JaanusKaapPublic/HyperViper)'s technology is partially included. 
    - Since the targets of these two fuzzers were different from my target, I developed a new fuzzer.
  - Architecture (/source [hAFL2](https://github.com/SafeBreach-Labs/hAFL2))
    ![Architecture.png](https://github.com/SafeBreach-Labs/hAFL2/blob/main/images/Architecture.png)
  - Sequence Diagram
     ```mermaid
      sequenceDiagram
    participant CPHarnless.sys
    participant storvsp.sys
    participant CrashMonitoring
    participant hAFL2
    hAFL2->>storvsp.sys: Check Coverage
    hAFL2->>CPHarnless.sys: Generate Payload
    CPHarnless.sys->>storvsp.sys: Send Payload
    loop CrashMonitoring
        CrashMonitoring->>storvsp.sys: Monitoring the crash
    end
    CrashMonitoring->>hAFL2: Crash Dump
      ```
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
