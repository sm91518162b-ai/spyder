# Spyder 🕷️
**550KB GPLv3 Antivirus with YARA + VirusTotal**

Built by a 12yo. This AV is completely free and fully functional. 
In the future we will contribute to AI research and children in foster homes. 
Enjoy free protection that feels premium.

## ⚠️ Requiere rules.yar
Spyder incluye el motor YARA, pero **NO las reglas**. Crea un archivo `rules.yar` antes de usar.

## Compilación
```bash
sudo apt install libyara-dev libcurl4-openssl-dev libssl-dev
g++ --std=c++17 -O3 -o spyder spyder.cpp -lyara -lcrypto -lcurl -pthread -w