# addjsif

Metasploit Exploit Module (MITM) for the Android addJavascriptInterface Issue that plagues Ad network framworks in Android apps. For more information see the references in the module itself.


## Motivation:

This project was executed in order to bring more attention to the severity of this issue.


## What is still needed:

More interface names per the list in the generate_getjsif method. These are the second (last) argument to the addJavascriptInterface function in the vulnerable WebView consumers. This will ensure the exploit works on the maximum number of vulnerable applications.


## Directions for testing:

### On your Metasploit host machine:

1. Check-out the http-proxy branch (not yet merged):

```
    $ git clone https://github.com/jduck/metasploit-framework.git -b http-proxy
```

NOTE: if you have an existing metasploit-framework checkout, you can download less data using the following commands instead:

```
    $ git add remote jduck https://github.com/jduck/metasploit-framework.git
    $ git fetch jduck
    $ git checkout jduck/http-proxy
```

2. Create the modules/exploits/android/mitm/http directory inside the checkout.

3. Place the module in modules/exploits/android/mitm/http directory.

4. Run the exploit module using a configuration similar to that in the included addjsif-exploit.msfrc file.

```
    $ msfconsole -nL -r addjsif-exploit.msfrc
```

### On your Android test device:

1. Go to Settings->Wi-Fi

2. Long press an existing connected network or connect to the one where the Metasploit instance lives.

3. Choose "Modify Network" if you are using an existing connection

4. Scroll to the bottom (both connecting and modifying now)

5. Check the "Show advanced options" box

6. Scroll down to "Proxy settings"

7. Choose "Manual" from the drop-down

8. Scroll down to see the "Proxy hostname" and "Proxy port" fields

9. Enter the Metasploit instance's IP address

10. Enter the Metasploit module's SRVPORT (8081 in the included msfrc)

11. Utilize vulnerable applications


## Known Issues:

The HTTP proxy code does not currently handle intercepting SSL traffic

Occasionally requests being transparently proxied may cause Metasploit to lag and stop responding. This can be fixed by:

```
    msf > threads -K
    msf > rexploit
```

The linux/armle/shell/reverse_tcp (staged payload) crashes on armv7


