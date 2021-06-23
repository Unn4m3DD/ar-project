from snimpy.manager import Manager as M
from snimpy.manager import load
from snimpy import mib
import time
import re
import argparse


def IPfromOctetString(t, s):
  if t == 1 or t == 3:
    return '.'.join([str(x) for x in s])
  elif t == 2 or t == 4:
    a = ':'.join(['{:02X}{:02X}'.format(s[i], s[i+1])
                 for i in range(0, 16, 2)])
    return re.sub(':{1,}:', '::', re.sub(':0*', ':', a))


def main():
  mib.path("./mibs/")
  load("SNMPv2-MIB")
  load("IF-MIB")
  load("IP-MIB")
  load("RFC1213-MIB")

  while(1):
    for i in [1, *range(3, 7)]:
      m = M(
          f"10.9.0.{i}",
          'private',
          3,
          secname='uDDR',
          authprotocol="MD5",
          authpassword="authpass",
          privprotocol="DES",
          privpassword="testpass"
      )
      print(f"hostname: {m.sysName} - 10.9.0.{i}", end="\n")

      print("software version: " + m.sysDescr.split("\n")[0])

      ip_dict = {str(x[1]): x[0] for x in m.ipAdEntIfIndex.items()}
      for ((i, name), (_, status)) in zip(m.ifDescr.items(), m.ifOperStatus.items()):
        if(str(status) == "up(1)"):
          print(f"{name}: {ip_dict[str(i)] if str(i) in ip_dict else status}")
    time.sleep(1)


if __name__ == "__main__":
  main()
