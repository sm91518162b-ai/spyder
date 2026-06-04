# Spyder 🕷️
**550KB GPLv3 Antivirus with YARA + VirusTotal**

Built by a 12yo. This AV is completely free and fully functional. 
In the future we will contribute to AI research and children in foster homes. 
Enjoy free protection that feels premium.

## ⚠️ Important: YARA Rules Required
Spyder **includes the YARA engine but NOT the rule files**. 
You must create a `rules.yar` file with malware signatures for Spyder to work.

**Quick setup with community rules:**
```bash
wget https://github.com/Yara-Rules/rules/archive/master.zip
unzip master.zip && cat rules-master/malware/*.yar > rules.yar