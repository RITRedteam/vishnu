DIRECTORY=bin
LINUX=linux-agent
WIN=windows-agent.exe
FLAGS=-ldflags "-s -w"
WIN-FLAGS=-ldflags -H=windowsgui

all: clean create-directory agent-windows agent-linux agent-linux-static

create-directory:
	mkdir ${DIRECTORY}

agent-windows:
	echo "Compiling Windows binary"
	env GOOS=windows GOARCH=amd64 go build ${WIN-FLAGS} -o ${DIRECTORY}/${WIN} main.go

agent-linux:
	echo "Compiling Linux binary"
	env GOOS=linux GOARCH=amd64 go build ${FLAGS} -o ${DIRECTORY}/${LINUX} main.go

agent-linux-static:
	echo "Compiling static Linux binary"
	docker run --rm=true -itv $(PWD):/mnt alpine:3.7 /mnt/build_static.sh
	
clean:
	rm -rf ${DIRECTORY}
