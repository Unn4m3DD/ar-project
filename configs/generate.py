import csv

cidr = {
"1" :	"128.0.0.0",
"2" :	"192.0.0.0",
"3" :	"224.0.0.0",
"4" :	"240.0.0.0",
"5" :	"248.0.0.0",
"6" :	"252.0.0.0",
"7" :	"254.0.0.0",
"8" :	"255.0.0.0",
"9" :	"255.128.0.0",
"10" :	"255.192.0.0",
"11" :	"255.224.0.0",
"12" :	"255.240.0.0",
"13" :	"255.248.0.0",
"14" :	"255.252.0.0",
"15" :	"255.254.0.0",
"16" :	"255.255.0.0",
"17" :	"255.255.128.0",
"18" :	"255.255.192.0",
"19" :	"255.255.224.0",
"20" :	"255.255.240.0",
"21" :	"255.255.248.0",
"22" :	"255.255.252.0",
"23" :	"255.255.254.0",
"24" :	"255.255.255.0",
"25" :	"255.255.255.128",
"26" :	"255.255.255.192",
"27" :	"255.255.255.224",
"28" :	"255.255.255.240",
"29" :	"255.255.255.248",
"30" :	"255.255.255.252",
"31" :	"255.255.255.254",
"32" :	"255.255.255.255"
}


with open('src.csv', newline='') as csvfile:
  reader = csv.reader(csvfile, delimiter="\t")
  last_name = ""
  ip_buffer = ""
  vlan_buffer = ""
  for row in reader:
    if(row[0] == ""): continue
    if(last_name != "" and last_name != row[0]):
      file = open(f"new_{last_name}.conf", "w")
      file.write("vlan database\n") 
      file.write(vlan_buffer) 
      file.write("exit\n") 
      file.write("conf t\n\n") 
      file.write(ip_buffer) 
      file.write("end\n") 
      file.close()
      ip_buffer = ""
      vlan_buffer = ""
    vlan_buffer += f"{row[1]}\n"
    ip_buffer += (f"""int {row[1]}
  ip add {row[2].split("/")[0]} {cidr[row[2].split("/")[1]]}
  ipv add {row[3]}\n\n""")
    last_name = row[0]