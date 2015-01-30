# ibpsolve
An openwrt package used to solve I, B, P frames in a H.264 format video

## Usage
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
