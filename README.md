# HAR Parser
A packcage that makes easier to parse requests using one click in DevTools.
No need for dumping browsers, one click and you are done :).

## Install
```shell
go get github.com/Wowkoltyy/harparser
```

## Example
```go
package main

import (
	"fmt"
	"harparser"
)

func main() {
  // parse from curl (DevTools: Copy request as CURL) file
	curl, err := harparser.ParseCURLFile("./assets/request.sh")
	if err != nil {
		panic(err)
	}
	fmt.Println(curl)
  // parse from .HAR file
	har, err := harparser.ParseHARFile("./assets/request.har", curl.URL.String())
	if err != nil {
		panic(err)
	}
	fmt.Println(har)

	fmt.Println(har.ChromeVersion)
	fmt.Println(curl.ChromeVersion)

  // you can also parse bytes

  curl2, err := harparser.ParseCURL([]byte("curl 'https://google.com' \\\n -H 'User-Agent: Mozilla/5.0'"))
	if err != nil {
		panic(err)
	}
	fmt.Println(curl2)

  // should return error, because har is empty
	har2, err := harparser.ParseRequestFromHAR([]byte("{}"), "https://google.com")
	if err == nil {
		panic(har2)
	}
	fmt.Println("err:", err)
}
```
