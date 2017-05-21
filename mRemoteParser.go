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
)

const sharedSecret = "mR3m"

type Node struct {
	XMLName  xml.Name `xml:"Node"`
	Name     string `xml:"Name,attr"`
	Type     string `xml:"Type,attr"`
	Username string `xml:"Username,attr"`
	Password string `xml:"Password,attr"`
	Hostname string `xml:"Hostname,attr"`
	Nodes    []Node `xml:"Node"`
}

type ConnectionConfig struct {
	XMLName xml.Name `xml:"Connections"`
	Name    string `xml:"Name,attr"`
	Nodes   []Node `xml:"Node"`
}

func (config ConnectionConfig) Print() {
	fmt.Printf("Config file: %s\n", config.Name)
	for _, node := range config.Nodes {
		node.Print()
	}
}

func (node Node) Print() {
	fmt.Printf("%s: %s", node.Type, node.Name)
	if node.Type == "Connection" {
		fmt.Printf(" (Hostname: %s, Username: %s, Password: %s)", node.Hostname, node.Username, node.Password)
	}
	fmt.Print("\n")
	for _, subNode := range node.Nodes {
		subNode.Print()
	}
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

func main() {
	fileName := "confCons.xml"
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Errorf("Could not read file: %s error: %config\n", fileName, err)
	}
	var config ConnectionConfig
	xmlErr := xml.Unmarshal([]byte(data), &config)
	if xmlErr != nil {
		fmt.Printf("error: %config", xmlErr)
		return
	}

	config.Print()

	pw := DecodePassword("WbPPpOXiHdwPSbAue+f0+/0DjVd2x/U43pf8Y+qnU3w=")
	fmt.Println(pw)

}
