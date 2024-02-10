# A/D cheat-sheet
## Deploy a service

```bash
# Clone a service
git clone https://github.com/SibirCTF/2023-service-sibirctf-sx
# Start a service from a directory with a docker-compose.yml file 
docker-compose up --build
# Open a port (if you need to share the service and you have a "white" IP)
sudo ufw allow 3080/tcp
# Check docker logs of docker container
docker logs -f conveyor-conveyor-1
```

