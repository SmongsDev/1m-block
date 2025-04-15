### Usage
```
syntax : 1m-block <site list file>
sample : 1m-block top-1m.txt
```

### Environment
```
sudo iptables -F
sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0
```

### Test
```
# HTTP로 강제 접속 (--no-check-certificate: HTTPS 인증서 검사 무시)
wget --no-check-certificate http://www.example.com

# 여러 사이트 테스트
wget --no-check-certificate http://google.com
wget --no-check-certificate http://facebook.com
```