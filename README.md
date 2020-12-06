# apsi-variants

This repository contains prototypes and benchmarks for "Novel Authorized Private Set Intersection Variants and Protocols", a research project for [CSCI2951E: Topics in Computer Systems Security](https://rtamassia.github.io/cs2951e/).


```
+--------+----------+-----------+-----------+------------------+------------------+--------------+------------------------+
|  SIZE  | INSECURE |   NAIVE   |   SETUP   | SIGNING (CLIENT) | SIGNING (SERVER) | INTERACTION  | INTERACTION (THREADED) |
+--------+----------+-----------+-----------+------------------+------------------+--------------+------------------------+
     10 & 13.6µs   & 809.8µs   & 30.1712ms & 63.2311ms        & 58.7054ms        & 23.1355ms    & 14.2967ms     \\
    100 & 252.6µs  & 105.3µs   & 34.0269ms & 578.9588ms       & 577.6586ms       & 207.9859ms   & 126.9793ms    \\
   1000 & 211.1µs  & 1.0331ms  & 36.0587ms & 6.4192662s       & 6.8396156s       & 2.8923881s   & 1.5088441s    \\
  10000 & 2.053ms  & 20.9596ms & 60.813ms  & 55.2823212s      & 1m0.9123086s     & 19.1990031s  & 9.8708209s    \\
 100000 & 9.3432ms & 56.771ms  & 28.5281ms & 5m40.5224947s    & 5m51.3867524s    & 4m9.0972045s & 1m43.6107824s \\
+--------+----------+-----------+-----------+------------------+------------------+--------------+------------------------+
```
