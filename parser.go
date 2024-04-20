package harparser

import (
	"bufio"
	"encoding/json"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	"github.com/mileusna/useragent"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type HAR struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Pages   []interface{} `json:"pages"`
		Entries []struct {
			Initiator *struct {
				Type  string `json:"type"`
				Stack struct {
					CallFrames []struct {
						FunctionName string `json:"functionName"`
						ScriptId     string `json:"scriptId"`
						Url          string `json:"url"`
						LineNumber   int    `json:"lineNumber"`
						ColumnNumber int    `json:"columnNumber"`
					} `json:"callFrames"`
				} `json:"stack"`
			} `json:"_initiator"`
			Priority     string `json:"_priority"`
			ResourceType string `json:"_resourceType"`
			Cache        *struct {
			} `json:"cache"`
			Connection string `json:"connection"`
			Request    *struct {
				Method      string `json:"method"`
				Url         string `json:"url"`
				HttpVersion string `json:"httpVersion"`
				Headers     []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				QueryString []interface{} `json:"queryString"`
				Cookies     []*struct {
					Name     string    `json:"name"`
					Value    string    `json:"value"`
					Path     string    `json:"path"`
					Domain   string    `json:"domain"`
					Expires  time.Time `json:"expires"`
					HttpOnly bool      `json:"httpOnly"`
					Secure   bool      `json:"secure"`
					SameSite string    `json:"sameSite"`
				} `json:"cookies"`
				HeadersSize int `json:"headersSize"`
				BodySize    int `json:"bodySize"`
				PostData    *struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
				} `json:"postData"`
			} `json:"request"`
			Response *struct {
				Status      int    `json:"status"`
				StatusText  string `json:"statusText"`
				HttpVersion string `json:"httpVersion"`
				Headers     []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				Cookies []struct {
					Name     string    `json:"name"`
					Value    string    `json:"value"`
					Path     string    `json:"path"`
					Domain   string    `json:"domain"`
					Expires  time.Time `json:"expires"`
					HttpOnly bool      `json:"httpOnly"`
					Secure   bool      `json:"secure"`
					SameSite string    `json:"sameSite"`
				} `json:"cookies"`
				Content struct {
					Size     int    `json:"size"`
					MimeType string `json:"mimeType"`
				} `json:"content"`
				RedirectURL  string      `json:"redirectURL"`
				HeadersSize  int         `json:"headersSize"`
				BodySize     int         `json:"bodySize"`
				TransferSize int         `json:"_transferSize"`
				Error        interface{} `json:"_error"`
			} `json:"response"`
			ServerIPAddress string    `json:"serverIPAddress"`
			StartedDateTime time.Time `json:"startedDateTime"`
			Time            int       `json:"time"`
			Timings         struct {
				Blocked         int `json:"blocked"`
				Dns             int `json:"dns"`
				Ssl             int `json:"ssl"`
				Connect         int `json:"connect"`
				Send            int `json:"send"`
				Wait            int `json:"wait"`
				Receive         int `json:"receive"`
				BlockedQueueing int `json:"_blocked_queueing"`
			} `json:"timings"`
		} `json:"entries"`
	} `json:"log"`
}

type RequestInfo struct {
	URL           *url.URL
	Header        http.Header
	XHeader       http.Header
	Cookies       []*http.Cookie
	UserAgent     useragent.UserAgent
	ChromeVersion int
}

// ParseRequestFromHAR Parses request given from HAR reader and returns the request by requestUrl info
func ParseRequestFromHAR(data []byte, requestUrl string) (*RequestInfo, error) {

	urlParsed, err := url.Parse(requestUrl)
	if err != nil {
		return nil, err
	}

	var har *HAR

	if err = json.Unmarshal(data, &har); err != nil {
		return nil, err
	}

	for _, entry := range har.Log.Entries {

		if entry.Request.Url == requestUrl {
			header := http.Header{}
			xHeader := http.Header{}
			cookies := make([]*http.Cookie, 0)
			var userAgent useragent.UserAgent
			chromeVersion := 0

			for _, h := range entry.Request.Headers {
				name := strings.ToLower(h.Name)
				if name == "cookie" {
					continue
				}
				if name == "user-agent" {
					userAgent = useragent.Parse(h.Value)
					uaParts := strings.Split(h.Value, "Chrome/")
					if len(uaParts) == 2 {
						temp := strings.Split(uaParts[1], " ")
						if len(temp) > 0 {
							chromeFullVersion := strings.Split(temp[0], ".")
							if len(chromeFullVersion) > 0 {
								chromeVersion, _ = strconv.Atoi(chromeFullVersion[0])
							}
						}
					}
				}
				if strings.HasPrefix(name, "x-") {
					xHeader.Add(h.Name, h.Value)
				} else {
					header.Add(h.Name, h.Value)
				}
			}
			for _, c := range entry.Request.Cookies {
				var sameSite http.SameSite
				switch c.SameSite {
				case "None":
					sameSite = http.SameSiteNoneMode
					break
				case "Strict":
					sameSite = http.SameSiteStrictMode
					break
				case "Lax":
					sameSite = http.SameSiteLaxMode
					break
				default:
					sameSite = http.SameSiteDefaultMode
				}

				cookies = append(cookies, &http.Cookie{
					Name:       c.Name,
					Value:      c.Value,
					Path:       c.Path,
					Domain:     c.Domain,
					Expires:    time.Time{},
					RawExpires: c.Expires.String(),
					Secure:     c.Secure,
					HttpOnly:   c.HttpOnly,
					SameSite:   sameSite,
				})
			}
			return &RequestInfo{
				Cookies:       cookies,
				XHeader:       xHeader,
				Header:        header,
				URL:           urlParsed,
				UserAgent:     userAgent,
				ChromeVersion: chromeVersion,
			}, nil
		}
	}
	return nil, NewErr("failed to find request in HAR file")
}

func ParseHARFile(path, requestUrl string) (*RequestInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRequestFromHAR(data, requestUrl)
}

func ParseCURL(data []byte) (*RequestInfo, error) {
	s := strings.TrimPrefix(string(data), "curl ")
	parts := strings.Split(s, "\\")
	if len(parts) < 1 {
		return nil, NewErr("curl is invalid")
	}

	urlPartUnparsed := strings.Split(parts[0], "'")
	if len(urlPartUnparsed) != 3 {
		return nil, NewErr("curl is invalid (cant parse url)")
	}
	urlParsed, err := url.Parse(urlPartUnparsed[1])
	if err != nil {
		return nil, err
	}

	header := http.Header{}
	xHeader := http.Header{}
	cookies := make([]*http.Cookie, 0)
	var userAgent useragent.UserAgent
	chromeVersion := 0

	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "-H") {
			headerUnparsed := strings.Split(part, "'")
			if len(headerUnparsed) != 3 {
				continue
			}
			headerParts := strings.Split(headerUnparsed[1], ":")
			if len(headerParts) != 2 {
				continue
			}
			headerParts[0] = strings.TrimSpace(headerParts[0])
			headerParts[1] = strings.TrimSpace(headerParts[1])
			name := strings.ToLower(headerParts[0])
			if name == "cookie" {
				cookies = ParseCookies(headerParts[1])
				continue
			}
			if name == "user-agent" {
				userAgent = useragent.Parse(headerParts[1])
				uaParts := strings.Split(headerParts[1], "Chrome/")
				if len(uaParts) == 2 {
					temp := strings.Split(uaParts[1], " ")
					if len(temp) > 0 {
						chromeFullVersion := strings.Split(temp[0], ".")
						if len(chromeFullVersion) > 0 {
							chromeVersion, _ = strconv.Atoi(chromeFullVersion[0])
						}
					}
				}
			}
			if strings.HasPrefix(name, "x-") {
				xHeader.Add(headerParts[0], headerParts[1])
			} else {
				header.Add(headerParts[0], headerParts[1])
			}
		}
	}
	return &RequestInfo{
		Cookies:       cookies,
		XHeader:       xHeader,
		Header:        header,
		URL:           urlParsed,
		UserAgent:     userAgent,
		ChromeVersion: chromeVersion,
	}, nil
}

func ParseCURLFile(path string) (*RequestInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCURL(data)
}

func ParseCookies(rawCookies string) []*http.Cookie {
	rawRequest := fmt.Sprintf("GET / HTTP/1.0\r\nCookie: %s\r\n\r\n", rawCookies)

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))

	if err != nil {
		return make([]*http.Cookie, 0)
	}
	return req.Cookies()
}

type Error struct {
	err string
}

func NewErr(err string) *Error {
	return &Error{err}
}

func (e *Error) Error() string {
	return e.err
}
