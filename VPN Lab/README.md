# SEED Lab 2.0 VPN

These instructions will only work for SEED lab 2.0 as it uses the docker folder structure

The instructions and code was taken from the following [blog post](https://blog.csdn.net/qq_39678161/article/details/126627332)

## Instructions

- [ ] Download and run the docker compose so that it creates the volumes folder
- [ ] Run the commands in `tls-stuff.sh` to create the certificates
- [ ] Copy the certs/python files so it has the following structure 

![test img](https://raw.githubusercontent.com/dev88jerry/CS325/main/VPN%20Lab/file%20structure.png)

- [ ] Run all 3 instances of the docker images
- [ ] Connect to the docker server and client and run their associated .py --> Use python3 in docker
- [ ] The .py will take up the entire terminal so you will need to open a new terminal to connect to both the server and client again
- [ ] Then ping/telnet the host-V ip as indicated in the docker compose
