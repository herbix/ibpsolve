# ibpsolve
An openwrt package used to parse I, B, P frames in an H.264 format video transferred via RSTP.

## Compile and Install
Move to your openwrt packages directory:
<pre>
$ cd /path/to/openwrt/package/
</pre>
Clone this repository:
<pre>
$ git clone https://github.com/herbix/ibpsolve.git
</pre>
Move back to openwrt directory and configure (Select -Utilities -ibpsolve [M]):
<pre>
$ cd /path/to/openwrt/
$ make menuconfig
</pre>
Save the configuration, then compile:
<pre>
$ make package/ibpsolve/compile
</pre>
You will get ipk file at bin directory:
<pre>
$ cd /path/to/openwrt/bin/&lt;device&gt;/packages/
$ ls -l ibpsolve*
</pre>
Finally, just copy this file to you openwrt device and install:
<pre>
$ scp ibpsolve_&lt;version&gt;_&lt;device&gt;.ipk &lt;your name&gt;@&lt;your device ip&gt;:ibpsolve_&lt;version&gt;_&lt;device&gt;.ipk
</pre>
<pre>
# opkg install ibpsolve_&lt;version&gt;_&lt;device&gt;.ipk
</pre>

## Usage
<pre>
# ibpsolve -h
Usage: ibpsolve [-v] [-p &lt;port&gt;] [-d &lt;device&gt;]
    -v            Run in verbose mode
    -p &lt;port&gt;     Specify an RTSP port
    -d &lt;device&gt;   Specify a device
Example:
    ibpsolve -v -p 554 -d wlan0
</pre>
Use this command to run ibpsolve as a deamon:
<pre>
# ibpsolve -p 554 -d any &
</pre>
And show reports:
<pre>
# cat current.txt
ID: B882913F [127.0.0.1:49663 -> 127.0.0.1:43006]
    During: Tue Feb  3 12:11:02 2015 - Tue Feb  3 12:12:15 2015
    Current Sequence Number: 36371
    Packets: 4693/4693 Total Bytes: 5021384 bytes Non-Frame Bytes: 0 bytes
    Frames: I:16(369559 bytes) P:692(3707761 bytes) B:1009(944064 bytes)

# cat history.txt
ID: 2BCFAEBC [127.0.0.1:45507 -> 127.0.0.1:54310]
    During: Sat Jan 31 19:43:39 2015 - Sat Jan 31 19:45:13 2015
    Current Sequence Number: 8423
    Packets: 7609/7609 Total Bytes: 8429943 bytes Non-Frame Bytes: 0 bytes
    Frames: I:22(1273229 bytes) P:943(6614106 bytes) B:1288(542608 bytes)

ID: FE2326AC [127.0.0.1:49790 -> 127.0.0.1:48452]
    During: Sat Jan 31 21:05:45 2015 - Sat Jan 31 21:09:23 2015
    Current Sequence Number: 53298
    Packets: 2460/2464 Total Bytes: 3042575 bytes Non-Frame Bytes: 0 bytes
    Frames: I:4(267222 bytes) P:216(2372126 bytes) B:196(359612 bytes)
</pre>
