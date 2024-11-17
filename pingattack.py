import subprocess
import time

targetIP = XYZ  #targetIP IP, found by going into cmd and typing 'ipconfig'

print(f"Starting ping attack on {targetIP}.")
try:
    while True:     #infinite loop of pinging until stopped
        if subprocess.call(["ping", "-n", "1", targetIP]) == 0: #sends single ping to target IP address
            print(f"Ping to {targetIP} successful.")            #confirmation if ping is successful
        else:
            print(f"Ping to {targetIP} blocked/failed.")        #confirmation if ping failed or gets blocked
        time.sleep(0.5)                 #time between each ping being sent out
except KeyboardInterrupt:               #control C to terminate attack
    print("\nPing attack stopped.")
