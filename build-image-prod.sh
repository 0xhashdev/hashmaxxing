docker build --build-arg USRNM=$(whoami) --build-arg USRUID=$(id -u) --build-arg USRGID=$(id -g) -t hashmaxxing:latest -f Dockerfile.prod .
