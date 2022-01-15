DIRECTORY=bin
LINUX=linux-agent
WIN=windows-agent.exe
FLAGS=-ldflags "-s -w"
WIN-FLAGS=-ldflags -H=windowsgui

all: clean create-directory agent-windows agent-linux

create-directory:
	mkdir ${DIRECTORY}

agent-windows:
	echo "Compiling Windows binary"
	env GOOS=windows GOARCH=amd64 go build ${WIN-FLAGS} -o ${DIRECTORY}/${WIN} main.go

agent-linux:
	echo "Compiling Linux binary"
	env GOOS=linux GOARCH=amd64 go build ${FLAGS} -o ${DIRECTORY}/${LINUX} main.go

clean:
	rm -rf ${DIRECTORY}
