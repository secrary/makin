I create `makin` to make initial malware assessment little bit easier for me, I think it's useful for others as well, It helps to reveal a debugger detection techniques used by a sample.

##### Any feedback is greatly appreciated: [@_qaz_qaz](https://twitter.com/_qaz_qaz)

#### Note: ~~Only supports x64~~ Supports x64 and x86

### How does it work?
`makin` opens a sample as a debuggee and injects `asho.dll`, `asho.dll` hooks several functions at `ntdll.dll` library and after parameters checkings, it sends the corresponding message to the debugger (`makin.exe`).

For hooking, it uses [Capstone engine](http://www.capstone-engine.org/), which makes hooking much stealthier.

`Note`: You can use [vcpkg](https://github.com/Microsoft/vcpkg) to get `Capstone`.

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
* `NtSystemDebugControl` - ref: [@waleedassar - pastebin](https://goo.gl/j4g5pV)
* `NtYieldExecution` - ref: The "Ultimate" Anti-Debugging Reference 7.D.xiii
* `NtSetLdtEntries` - ref: [ANTI-UNPACKER TRICKS: PART ONE - 2.1.2](https://web.archive.org/web/20171215191103/http://pferrie.tripod.com/papers/unpackers21.pdf)
* `NtQueryInformationThread` ref: [ntquery - NtQueryInformationThread](https://web.archive.org/web/20180110063515/https://ntquery.wordpress.com/2014/03/29/anti-debug-ntsetinformationthread/)

That's all for now, you can add as much as you wish :) 

### TODO: 
* [DONE] ~~Use a disassembler such as [capstone](http://www.capstone-engine.org/) to hook little bit deeper and avoid simple hook checks.~~

* At this moment, `makin` does not support child processes.

* Add more tricks.

* [DONE] ~~x86 support~~

* add anti-vm, anti-emulation tricks detection

##### DEMO:

![makin_demo](https://user-images.githubusercontent.com/16405698/33871171-c6f8a156-df2a-11e7-8ffb-b9ae5c030c48.gif)
