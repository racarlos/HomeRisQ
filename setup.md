# Development Set-up
## Prerequisites
* Python v3.8 or later 
* PIP v20.3.4 or later 
* GVM v21.4.3 or later
* Kivy v2.1.0 or later
* KivyMD v0.104.2 or later
* Working Internet Connection
* Device used for testing the app is connected to network device

## Instructions

1. Install dependencies using the following commands: 
```
sudo apt update -y
sudo apt install gvm python3.9 -y 
```

2. Run the following commands to setup gvm:
```
sudo gvm-setup
```

3. Double check if everything is installed and configured correctly:
```
sudo gvm-check-setup
```

4. Update GVM Feeds, SCAP, and CERT Data (Do one at a time)
```
greenbone-feed-sync --type GVMD_DATA
greenbone-feed-sync --type SCAP
greenbone-feed-sync --type CERT
```

5. Install GUI package dependencies using `pip`:
```
pip install "kivy[full]"
pip install kivymd
```

6. Run the following command to use the program:
```
sudo gvm-start
sudo python3 main.py
```
