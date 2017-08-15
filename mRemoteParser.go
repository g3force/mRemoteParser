package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"encoding/base64"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"bytes"
	"github.com/schollz/closestmatch"
	"flag"
	"strings"
	"os"
)

const sharedSecret = "mR3m"

var fileName = flag.String("f", "confCons.xml", "The config file containing the connections")
var listConnections = flag.Bool("l", false, "List all connections")

type Container struct {
	Name  string `xml:"Name,attr"`
	Nodes []Node `xml:"Node"`
}

type Node struct {
	XMLName  xml.Name `xml:"Node"`
	Type     string `xml:"Type,attr"`
	Username string `xml:"Username,attr"`
	Password string `xml:"Password,attr"`
	Hostname string `xml:"Hostname,attr"`
	HomeDir  string `xml:"UserField,attr"`
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
		str += fmt.Sprintf("%s -> Hostname: %s, Home: %s, Username: %s, Password: %s", node.Name, node.Hostname, node.HomeDir, node.Username, node.Password)
	} else if node.Type == "Container" {
		str += fmt.Sprintf("%s\n", node.Name)
	}
	for _, subNode := range node.Nodes {
		str += subNode.String() + "\n"
	}
	return
}

func DecodePassword(base64DecodedEncryptedPassword string) (decodedPassword string) {
	encryptedPassword, err := base64.StdEncoding.DecodeString(base64DecodedEncryptedPassword)
	if err != nil {
		panic(err.Error())
	}

	key16 := md5.Sum([]byte(sharedSecret))
	privateKey := key16[:]

	// IV: Initialization Vector
	iv := encryptedPassword[:aes.BlockSize]
	cipherText := encryptedPassword[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(cipherText)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	cipherBlock, err := aes.NewCipher(privateKey)
	if err != nil {
		panic(err.Error())
	}
	cbc := cipher.NewCBCDecrypter(cipherBlock, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	cbc.CryptBlocks(cipherText, cipherText)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which will
	// be removed here
	lastChar := cipherText[len(cipherText)-1]
	if lastChar < 33 || lastChar > 126 {
		cipherText = bytes.Trim(cipherText, string(lastChar))
	}

	decodedPassword = string(cipherText)

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
	bagSize := []int{2,3,4}
	cm := closestmatch.New(dict, bagSize)
	match := cm.Closest(strings.ToLower(query))

	for _, connection := range connections {
		if connection.Name == match {
			node = connection.Node
			return
		}
	}

	panic("Could find any connection")
}

func (node Node) ConnectCommand() string {
	password := DecodePassword(node.Password)
	return fmt.Sprintf("sshpass -p '%s' ssh -o StrictHostKeyChecking=no -t %s@%s 'cd %s; bash'", password, node.Username, node.Hostname, node.HomeDir)
}

func main() {

	flag.Parse()

	data, err := ioutil.ReadFile(*fileName)
	if err != nil {
		panic(fmt.Sprintf("Could not read file: %s error: %config\n", *fileName, err))
	}

	var config ConnectionConfig
	xmlErr := xml.Unmarshal([]byte(data), &config)
	if xmlErr != nil {
		panic(fmt.Sprintf("error: %config", xmlErr))
	}

	if *listConnections {
		fmt.Fprintln(os.Stderr, config)
		return
	}

	connectQuery := strings.Join(flag.Args(), " ")

	if len(connectQuery) > 0 {
		node := config.closestMatch(connectQuery)
		fmt.Fprintf(os.Stderr, "Connecting to %v\n", node)
		fmt.Println(node.ConnectCommand())
	}
}
