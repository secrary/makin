I create `makin` to make initial malware assessment little bit easier for me, I think it's useful for others as well, It helps to reveal a debugger detection techniques used by a sample.

### How does it work?
`makin` opens a sample as a debuggee and injects `asho.dll`, `asho.dll` hooks several functions at `ntdll.dll` library and after parameters checkings, it sends the corresponding message to the debugger (`makin.exe`).

At this moment, `makin` can reveal following techniques: 

`Note`: Use [`The “Ultimate” Anti-Debugging  Reference` as a reference](https://web.archive.org/web/20171212061916/http://pferrie.host22.com/papers/antidebug.pdf)
* `NtClose`: ref: The "Ultimate" Anti-Debugging Reference: 7.B.ii
* `NtOpenProcess`: ref: The "Ultimate" Anti-Debugging Reference: 7.B.i
* `NtCreateFile`: ref: The "Ultimate" Anti-Debugging Reference: 7.B.iii (Open itself)
* `NtCreateFile`: ref: The "Ultimate" Anti-Debugging Reference: 7.B.iii (Open a driver)
* `LdrLoadDll`- ref: The "Ultimate" Anti-Debugging Reference: 7.B.iv
* `NtSetDebugFilterState` - ref: The "Ultimate" Anti-Debugging Reference: 7.D.vi
* `NtQueryInformationProcess` - ref: The "Ultimate" Anti-Debugging Reference: 7.D.viii.a, 7.D.viii.b, 7.D.viii.c
* `NtQuerySystemInformation` - ref: The "Ultimate" Anti-Debugging Reference: 7.E.iii
* `NtSetInformationThread` - ref: The "Ultimate" Anti-Debugging Reference 7.F.iii
* `NtCreateUserProcess` - ref: The "Ultimate" Anti-Debugging Reference 7.G.i
* `NtCreateThreadEx` - ref: [ntuery blog post](https://web.archive.org/web/20171211143522/https://ntquery.wordpress.com/2014/03/29/anti-debug-ntcreatethreadex/)

That's all for now, you can add as much as you wish :) 

### TODO: 
Use a disassembler such as [capstone](http://www.capstone-engine.org/) to hook little bit deeper and avoid simple hook checks.

At this moment, `makin` does not support child processes.

Add more tricks.

##### DEMO: `NtCreateThreadEx`:

![makin_demo](https://user-images.githubusercontent.com/16405698/33871171-c6f8a156-df2a-11e7-8ffb-b9ae5c030c48.gif)
