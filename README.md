This is a proof of concept to show how to protect your linux system against keyloggers running from the userspace environment.


- Invoking python to run a script that will call the input subsystem results in killing the python process by input-guardian resulting in terminating it's own process
    * Write a check to prevent killing the python process
- Not protected against the kill signal
    * Detect the kill signal en start a new process from the input-guardian script
- Not protected against removing the input-guardian script and then killing the input-guardian process
    * Write the source code from the running process to a file when recieving the kill signal en run the program before the process is killed
- Not protected against processes running in kernelspace.

create a whitelist of kernel modules
rmmod and insmod every day

http://ieeexplore.ieee.org/xpl/login.jsp?tp=&arnumber=6337496&url=http%3A%2F%2Fieeexplore.ieee.org%2Fxpls%2Fabs_all.jsp%3Farnumber%3D6337496