package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/schollz/closestmatch"
	"golang.org/x/crypto/pbkdf2"
)

/** The shared secret seems to be build into mRemote */
const sharedSecret = "mR3m"

var fileName = flag.String("f", "", "The config file containing the connections")
var listConnections = flag.Bool("l", false, "List all connections")
var printPassword = flag.Bool("p", false, "Print password of connection")
var execCommand = flag.String("c", "", "Execute a single command")

type Container struct {
	Name  string `xml:"Name,attr"`
	Nodes []Node `xml:"Node"`
}

type Node struct {
	XMLName  xml.Name `xml:"Node"`
	Type     string   `xml:"Type,attr"`
	Username string   `xml:"Username,attr"`
	Password string   `xml:"Password,attr"`
	Hostname string   `xml:"Hostname,attr"`
	HomeDir  string   `xml:"UserField,attr"`
	Port     string   `xml:"Port,attr"`
	Container
}

type Connection struct {
	Path string
	Node
}

type ConnectionConfig struct {
	XMLName xml.Name `xml:"Connections"`
	Container
}

func (config ConnectionConfig) String() (str string) {
	str = fmt.Sprintf("Config file: %s\n", config.Name)
	for _, node := range config.Nodes {
		str += node.String() + "\n"
	}
	return
}

func (node Node) String() (str string) {
	if node.Type == "Connection" {
		encPassword, _ := DecodePassword(node.Password)
		str += fmt.Sprintf("%s -> %s@%s:%s Password: %s", node.Name, node.Username, node.Hostname, node.HomeDir, encPassword)
	} else if node.Type == "Container" {
		str += fmt.Sprintf("%s\n", node.Name)
	}
	for _, subNode := range node.Nodes {
		str += subNode.String() + "\n"
	}
	return
}

func DecodePassword(base64DecodedEncryptedPassword string) (decodedPassword string, err error) {
	if len(base64DecodedEncryptedPassword) == 0 {
		return "", errors.New("password is empty")
	}
	encryptedPassword, err := base64.StdEncoding.DecodeString(base64DecodedEncryptedPassword)
	if err != nil {
		return "", err
	}

	salt := encryptedPassword[:aes.BlockSize]
	nonce := encryptedPassword[aes.BlockSize:(2 * aes.BlockSize)]
	cipherText := encryptedPassword[(2 * aes.BlockSize):]

	key := pbkdf2.Key([]byte(sharedSecret), []byte(salt), 1000, 32, sha1.New)

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCMWithNonceSize(cipherBlock, 16)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, cipherText, []byte(salt))
	if err != nil {
		return "", err
	}

	decodedPassword = string(plaintext)

	return
}

func (node Container) FillConnectionMap(connections []Connection, path string) (newConnections []Connection) {
	newConnections = connections
	for _, subNode := range node.Nodes {
		if subNode.Type == "Connection" {
			var connection Connection
			connection.Node = subNode
			connection.Path = path + " " + subNode.Name
			newConnections = append(newConnections, connection)
		} else {
			newPath := path + " " + subNode.Name
			newConnections = subNode.FillConnectionMap(newConnections, newPath)
		}

	}
	return newConnections
}

func buildDict(connections []Connection) (dict []string) {
	for _, node := range connections {
		dict = append(dict, node.Name)
	}
	return
}

func (config ConnectionConfig) closestMatch(query string) (node Node) {
	connections := config.FillConnectionMap([]Connection{}, "")
	dict := buildDict(connections)
	bagSize := []int{2, 3, 4}
	cm := closestmatch.New(dict, bagSize)
	match := cm.Closest(strings.ToLower(query))

	for _, connection := range connections {
		if connection.Name == match {
			node = connection.Node
			return
		}
	}

	panic("Could not find any connection")
}

func (node Node) ConnectCommand() error {
	return node.ExecCommand("bash")
}

func (node Node) ExecCommand(command string) error {
	if len(node.Password) == 0 {
		cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", "-p", node.Port, "-t", node.Username+"@"+node.Hostname, "cd "+node.HomeDir+"; "+command)
		return interactiveConsole(cmd)
	}
	password, err := DecodePassword(node.Password)
	if err != nil {
		fmt.Printf("Could not decode password: %v\n", err)
		return err
	}
	cmd := exec.Command("sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", "-p", node.Port, "-t", node.Username+"@"+node.Hostname, "cd "+node.HomeDir+"; "+command)
	return interactiveConsole(cmd)
}

func interactiveConsole(cmd *exec.Cmd) error {
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	return err
}

func main() {

	flag.Parse()

	if fileName == nil || len(*fileName) == 0 {
		*fileName = os.Getenv("MREMOTE_CONFIG_FILE")
	}

	data, err := ioutil.ReadFile(*fileName)
	if err != nil {
		fmt.Printf("Could not read file '%s': %v\n", *fileName, err)
		return
	}

	var config ConnectionConfig
	xmlErr := xml.Unmarshal([]byte(data), &config)
	if xmlErr != nil {
		fmt.Printf("Error while parsing XML config: %v\n", xmlErr)
		return
	}

	if *listConnections {
		fmt.Println(config)
		return
	}

	connectQuery := strings.Join(flag.Args(), " ")

	if len(connectQuery) > 0 {
		node := config.closestMatch(connectQuery)
		fmt.Printf("Connection: %v\n", node)
		if *printPassword {
			password, err := DecodePassword(node.Password)
			if err != nil {
				fmt.Printf("Could not decode password: %v\n", err)
			} else {
				fmt.Printf("Password: %v\n", password)
			}
		} else if len(*execCommand) > 0 {
			err := node.ExecCommand(*execCommand)
			if err != nil {
				fmt.Printf("Connection failed: %v\n", err)
			}
		} else {
			err := node.ConnectCommand()
			if err != nil {
				fmt.Printf("Connection failed: %v\n", err)
			}
		}
	}
}
