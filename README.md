### Usage
```
syntax : 1m-block <site list file>
sample : 1m-block top-1m.txt
```

### environment
```
sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
```
