package bindata

import (
	"time"

	"github.com/jessevdk/go-assets"
)

var _Assetsba03ce8c43da0753553b805caccbff245b883390 = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n\t<meta charset=\"utf-8\">\n\t<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n\t<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\n\t<title>{{.Code}}:{{.Message}}</title>\n    <link rel=\"stylesheet\" type=\"text/css\" href=\"https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.4.1/semantic.min.css\"></link>\n    <style type=\"text/css\">\n        body {\n        background-color: #DADADA;\n        }\n        body > .grid {\n        height: 100%;\n        }\n        .image {\n        margin-top: -100px;\n        }\n        .column {\n        max-width: 600px;\n        }\n        .masthead h1.ui.header {\n            font-size: 7em;\n            font-weight: normal;\n        }\n        .masthead h2 {\n        font-size: 3em;\n        font-weight: normal;\n        }\n    </style>\n</head>\n\n<body>\n    <div class=\"ui middle aligned center aligned grid masthead\">\n        <div class=\"column\">\n            <h1 class=\"ui header\">{{.Code}}</h1>\n            <h2  class=\"ui header\">{{.Message}}</h2>\n            <p>\n                <a class=\"ui labeled icon button blue\" href=\"/\">\n                    <i class=\"angle double up icon\"></i>\n                    Go to Top\n                </a>\n                <a class=\"ui labeled icon button teal\" href=\"/login\">\n                    <i class=\"sign-in icon\"></i>\n                    Sign In\n                </a>\n            </p>\n        </div>\n    </div>\n</body>\n</html>\n"

// Assets returns go-assets FileSystem
var Assets = assets.NewFileSystem(map[string][]string{"/": []string{"assets"}, "/assets": []string{}, "/assets/html": []string{"error.html.tpl"}}, map[string]*assets.File{
	"/": &assets.File{
		Path:     "/",
		FileMode: 0x800001ff,
		Mtime:    time.Unix(1549202245, 1549202245010749100),
		Data:     nil,
	}, "/assets": &assets.File{
		Path:     "/assets",
		FileMode: 0x800001ff,
		Mtime:    time.Unix(1549178988, 1549178988864132100),
		Data:     nil,
	}, "/assets/html": &assets.File{
		Path:     "/assets/html",
		FileMode: 0x800001ff,
		Mtime:    time.Unix(1549178852, 1549178852583863000),
		Data:     nil,
	}, "/assets/html/error.html.tpl": &assets.File{
		Path:     "/assets/html/error.html.tpl",
		FileMode: 0x1b6,
		Mtime:    time.Unix(1549204445, 1549204445930518300),
		Data:     []byte(_Assetsba03ce8c43da0753553b805caccbff245b883390),
	}}, "")
