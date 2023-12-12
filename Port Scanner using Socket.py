# ok, going to import the right modules to start. Those would be 'Socket' and 'time'
from socket import *
import time
startTime = time.time()

# now to write the script for the port scanner. I am going to scan the port scanning practice site 'scanme.nmap.org/.
# Don't scan networks without expressed permission from the owners.
if __name__ == '__main__':
    target = input('Enter the host to be scanned: ')
    t_IP = gethostbyname(target)
    print('Starting scan on host: ', t_IP)
# I am only scanning the range of 50-500 below. I can change the range if desired.
    for i in range(50, 500):
        s = socket(AF_INET, SOCK_STREAM)

        conn = s.connect_ex((t_IP, i))
        if (conn == 0):
            print('Port %d: OPEN' % (i,))
        s.close()
print('Time taken:', time.time() - startTime)
# When the script is run, it'll prompt you for the host you wish to scan. Pretty cool!
# Again, only scan hosts and networks where you have permission to do so!!!